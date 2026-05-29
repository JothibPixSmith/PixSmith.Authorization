using PixSmith.Authorization.Infrastructure.OpenIddict;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Validation.AspNetCore;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Repositories;
using PixSmith.Authorization.Repositories.Interfaces;
using PixSmith.Authorization.Services;
using PixSmith.Authorization.Services.Interfaces;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PixSmith.Authorization.API;

public static class InfrastructureServiceExtensions
{
	public static IServiceCollection AddInfrastructure(
		this IServiceCollection services,
		IConfiguration configuration,
		IHostEnvironment environment)
	{
		// ─── Data Protection ──────────────────────────────────────────────
		// Persist keys to a directory so OpenIddict signing certs survive restarts.
		// In containers, mount this path as a volume. In dev, the default in-memory
		// store is used unless DataProtection:KeyPath is set.

		var keyPath = configuration["DataProtection:KeyPath"];
		if (!string.IsNullOrEmpty(keyPath))
		{
			services.AddDataProtection()
				.PersistKeysToFileSystem(new DirectoryInfo(keyPath));
		}

		// ─── Forwarded Headers ─────────────────────────────────────────────
		// Required when running behind a reverse proxy (nginx, Traefik, etc.)
		// in a container so that the app sees the original scheme and host.

		services.Configure<ForwardedHeadersOptions>(options =>
		{
			options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
			// Trust all proxies within a Docker network; restrict to known IPs in production.
			options.KnownIPNetworks.Clear();
			options.KnownProxies.Clear();
		});

		// ─── EF Core ───────────────────────────────────────────────────────

		var connectionString = configuration.GetConnectionString("DefaultConnection")
			?? throw new InvalidOperationException("ConnectionStrings:DefaultConnection is required.");

		services.AddDbContext<ApplicationDbContext>(options =>
		{
			options.UseSqlite(connectionString);

			// Register EF Core entity sets for OpenIddict (uses Guid PKs)
			options.UseOpenIddict<Guid>();
		});

		// ─── ASP.NET Identity ──────────────────────────────────────────────

		var pwd = configuration.GetSection("Identity:Password");
		var lockout = configuration.GetSection("Identity:Lockout");

		services.AddIdentity<IdentityUser<Guid>, IdentityRole<Guid>>(options =>
		{
			options.Password.RequiredLength          = pwd.GetValue<int>("RequiredLength", 8);
			options.Password.RequireDigit            = pwd.GetValue<bool>("RequireDigit", true);
			options.Password.RequireUppercase        = pwd.GetValue<bool>("RequireUppercase", true);
			options.Password.RequireNonAlphanumeric  = pwd.GetValue<bool>("RequireNonAlphanumeric", true);
			options.Lockout.MaxFailedAccessAttempts  = lockout.GetValue<int>("MaxFailedAccessAttempts", 5);
			options.Lockout.DefaultLockoutTimeSpan   = TimeSpan.FromMinutes(lockout.GetValue<int>("DefaultLockoutTimeSpanMinutes", 15));
			options.User.RequireUniqueEmail          = true;
			options.SignIn.RequireConfirmedEmail      = false;
		})
		.AddEntityFrameworkStores<ApplicationDbContext>()
		.AddDefaultTokenProviders();

		// ─── OpenIddict ────────────────────────────────────────────────────

		services.AddOpenIddict()
			.AddCore(options =>
			{
				options.UseEntityFrameworkCore()
					.UseDbContext<ApplicationDbContext>()
					.ReplaceDefaultEntities<Guid>();
			})
			.AddServer(options =>
			{
				// Well-known endpoints
				options.SetAuthorizationEndpointUris("/connect/authorize")
					   .SetTokenEndpointUris("/connect/token")
					   .SetUserInfoEndpointUris("/connect/userinfo")
					   .SetEndSessionEndpointUris("/connect/logout")
					   .SetIntrospectionEndpointUris("/connect/introspect")
					   .SetRevocationEndpointUris("/connect/revoke")
					   .SetJsonWebKeySetEndpointUris("/.well-known/jwks");

				// Supported flows
				options.AllowAuthorizationCodeFlow()
					   .AllowClientCredentialsFlow()
					   .AllowPasswordFlow()
					   .AllowRefreshTokenFlow()
					   .RequireProofKeyForCodeExchange();

				// Supported scopes
				options.RegisterScopes(
					Scopes.Email, Scopes.Profile, Scopes.Roles,
					Scopes.OpenId, Scopes.OfflineAccess, "api", "admin");

				// Signing/encryption keys.
				// In production, replace with X.509 certs loaded from secrets or Key Vault.
				// Ephemeral keys are fine for single-instance containers; tokens are
				// invalidated on restart. Dev certs persist via the data-protection store.
				if (environment.IsDevelopment())
				{
					options.AddDevelopmentEncryptionCertificate()
						   .AddDevelopmentSigningCertificate();
				}
				else
				{
					options.AddEphemeralEncryptionKey()
						   .AddEphemeralSigningKey();
				}

				options.UseAspNetCore()
					.EnableAuthorizationEndpointPassthrough()
					.EnableTokenEndpointPassthrough()
					.EnableUserInfoEndpointPassthrough()
					.EnableEndSessionEndpointPassthrough()
					.EnableStatusCodePagesIntegration();
			})
			.AddValidation(options =>
			{
				options.UseLocalServer();
				options.UseAspNetCore();
			});

		// ─── Authorization Policies ─────────────────────────────
		// Use these on API endpoints that should accept bearer tokens
		// (both from user OIDC flows and M2M client credentials).

		services.AddAuthorization(options =>
		{
			// Requires a valid bearer token with the "api" scope.
			options.AddPolicy("ApiAccess", policy =>
			{
				policy.AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
				policy.RequireAuthenticatedUser();
				policy.RequireClaim(Claims.Private.Scope, Scopes.OfflineAccess, "api");
			});

			// Requires a valid bearer token and the "Admin" role (for user-issued tokens)
			// or the "admin" scope (for M2M tokens).
			// Use HasClaim with the JWT short-form claim type ("role") rather than IsInRole,
			// because the ClaimsIdentity rebuilt by OpenIddict validation uses the default
			// Windows-URI RoleClaimType which does not match the JWT "role" claim.
			options.AddPolicy("AdminAccess", policy =>
			{
				policy.AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
				policy.RequireAuthenticatedUser();
				policy.RequireAssertion(ctx =>
					ctx.User.HasClaim(Claims.Role, "Admin") ||
					ctx.User.HasClaim(Claims.Private.Scope, "admin"));
			});
		});

		// Internal loopback client used by AccountController.Login to call /connect/token.
		// Trusts the localhost dev certificate so HTTPS works without extra setup.
		services.AddHttpClient("Self").ConfigurePrimaryHttpMessageHandler(() =>
			new HttpClientHandler
			{
				ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) =>
					msg.RequestUri?.Host is "localhost" or "127.0.0.1" ||
					errors == System.Net.Security.SslPolicyErrors.None
			});

		// ─── Repositories ───────────────────────────────────────

		services.AddTransient<IOAuthClientRepository, OAuthClientRepository>();
		services.AddTransient<IUserRepository, UserRepository>();
		services.AddTransient<ITenantRepository, TenantRepository>();

		// ─── Services ───────────────────────────────────────

		services.AddTransient<IPasswordHashingService, PasswordHashingService>();
		services.AddTransient<IEmailService, EmailService>();

		services.AddTransient<IUserService, UserService>();
		services.AddTransient<IAccountService, AccountService>();
		services.AddTransient<IAdminService, AdminService>();
		services.AddTransient<IConnectService, ConnectService>();
		services.AddTransient<IOAuthClientService, OAuthClientService>();
		services.AddTransient<ITenantService, TenantService>();
		services.AddScoped<IOidcAppService, OidcAppService>();

		services.AddHostedService<OpenIddictSeeder>();


		return services;
	}
}
