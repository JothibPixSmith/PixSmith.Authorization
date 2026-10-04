using PixSmith.Authorization.Infrastructure.OpenIddict;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection.Extensions;
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

		var databaseProvider = configuration.GetValue("Database:Provider", "Sqlite")!;

		services.AddDbContext<ApplicationDbContext>(options =>
		{
			switch (databaseProvider)
			{
				case "Postgres":
				case "PostgreSql":
					options.UseNpgsql(connectionString, npgsql =>
						npgsql.MigrationsAssembly("PixSmith.Authorization.DataContext.Migrations.Postgres"));
					break;
				case "Sqlite":
					options.UseSqlite(connectionString, sqlite =>
						sqlite.MigrationsAssembly("PixSmith.Authorization.DataContext.Migrations.Sqlite"));
					break;
				default:
					throw new InvalidOperationException(
						$"Unsupported Database:Provider '{databaseProvider}'. Supported values: Sqlite, Postgres.");
			}

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
			options.SignIn.RequireConfirmedEmail      = true;
		})
		.AddEntityFrameworkStores<ApplicationDbContext>()
		.AddDefaultTokenProviders();

		// The application cookie is the shared SSO session. /connect/authorize challenges
		// this scheme, so LoginPath must point at the server-rendered login page —
		// Identity's default (/Account/Login as a Razor Page) does not exist in this app.
		services.ConfigureApplicationCookie(options =>
		{
			options.LoginPath        = "/Account/Login";
			options.LogoutPath       = "/Account/Logout";
			options.AccessDeniedPath = "/Account/AccessDenied";
			options.ExpireTimeSpan   = TimeSpan.FromHours(8);
			options.SlidingExpiration = true;

			// Lax (the default) is required, not Strict: the browser arrives at
			// /connect/authorize as a cross-site redirect from the client app and the
			// cookie must be sent on that top-level GET or SSO silently fails.
			options.Cookie.SameSite = SameSiteMode.Lax;
			options.Cookie.HttpOnly = true;
			options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
		});

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

				// Issue access tokens as plain signed JWTs rather than encrypted JWEs.
				// Required for external resource servers: they validate tokens against
				// /.well-known/jwks and cannot decrypt a JWE. ID tokens are signed-only
				// either way, and refresh/authorization codes stay encrypted.
				options.DisableAccessTokenEncryption();

				// Supported scopes
				options.RegisterScopes(
					Scopes.Email, Scopes.Profile, Scopes.Roles,
					Scopes.OpenId, Scopes.OfflineAccess, "api", "admin");

				// Token signing and encryption keys. Required outside Development and
				// Testing — see OpenIddictCertificates for why startup is refused rather
				// than silently falling back to keys that rotate on every restart.
				Security.OpenIddictCertificates.Configure(options, configuration, environment);

				var aspNetCore = options.UseAspNetCore()
					.EnableAuthorizationEndpointPassthrough()
					.EnableTokenEndpointPassthrough()
					.EnableUserInfoEndpointPassthrough()
					.EnableEndSessionEndpointPassthrough()
					.EnableStatusCodePagesIntegration();

				if (environment.IsDevelopment())
				{
					// The debug container serves plain HTTP on 8080; without this every
					// protocol endpoint returns "This server only accepts HTTPS requests".
					// Production keeps the requirement — and behind a proxy, the
					// UseForwardedHeaders call above lets OpenIddict see the original
					// https scheme, so terminating TLS at the proxy still works.
					aspNetCore.DisableTransportSecurityRequirement();
				}
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

			// Administering the authorization server requires BOTH the "Admin" role and the
			// "admin" scope. They answer different questions and neither is sufficient alone:
			//
			//   role  — who the user is.   Without it, a machine client granted "admin" scope
			//           could administer the server with no human involved at all.
			//   scope — what this client was authorized to do. Without it, every token issued
			//           to an administrator can administer, including tokens held by unrelated
			//           applications they happen to sign in to — a confused deputy.
			//
			// Requiring both means only a client explicitly granted admin authority, used by
			// someone who actually holds it, can reach this API. A client-credentials token
			// carries no role claim at all, so machine identities are excluded outright.
			//
			// Use HasClaim with the JWT short-form claim type ("role") rather than IsInRole,
			// because the ClaimsIdentity rebuilt by OpenIddict validation uses the default
			// Windows-URI RoleClaimType which does not match the JWT "role" claim.
			options.AddPolicy("AdminAccess", policy =>
			{
				policy.AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
				policy.RequireAuthenticatedUser();
				policy.RequireAssertion(ctx =>
					ctx.User.HasClaim(Claims.Role, "Admin") &&
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
		services.AddTransient<ITenantMembershipRepository, TenantMembershipRepository>();
		services.AddTransient<ITenantApplicationRepository, TenantApplicationRepository>();

		// ─── Email ────────────────────────────────────────────

		services.Configure<EmailOptions>(configuration.GetSection("Email"));
		services.AddTransient<ISmtpSender, MailKitSmtpSender>();
		services.AddTransient<IEmailOutbox, EmailOutbox>();
		services.AddHostedService<EmailOutboxDispatcher>();

		// ─── Services ───────────────────────────────────────

		// ─── Tenant Provisioning ────────────────────────────────
		// Public keys are bound from configuration only. See TenantProvisioningOptions for
		// why they must never be sourced from the database this control protects.

		services.Configure<TenantProvisioningOptions>(
			configuration.GetSection(TenantProvisioningOptions.SectionName));
		services.Configure<TenantBackfillOptions>(
			configuration.GetSection(TenantBackfillOptions.SectionName));
		services.Configure<TenantEnforcementOptions>(
			configuration.GetSection(TenantEnforcementOptions.SectionName));
		services.TryAddSingleton(TimeProvider.System);
		services.AddScoped<IProvisioningAuthorizer, ProvisioningAuthorizer>();

		// Audit needs the ambient request to attribute an action to a person.
		services.AddHttpContextAccessor();
		services.AddTransient<IAuditService, AuditService>();

		services.AddTransient<IPasswordHashingService, PasswordHashingService>();
		services.AddTransient<IEmailService, EmailService>();

		services.AddTransient<IUserService, UserService>();
		services.AddTransient<IAccountService, AccountService>();
		services.AddTransient<IAdminService, AdminService>();
		services.AddTransient<ITenantContextResolver, TenantContextResolver>();
		services.AddTransient<ITenantAccessPolicy, TenantAccessPolicy>();
		services.AddTransient<IConnectService, ConnectService>();
		services.AddTransient<IOAuthClientService, OAuthClientService>();
		services.AddTransient<ITenantService, TenantService>();
		services.AddScoped<IOidcAppService, OidcAppService>();
		services.AddScoped<IOidcScopeService, OidcScopeService>();
		services.AddTransient<ITenantAccessService, TenantAccessService>();

		services.AddHostedService<OpenIddictSeeder>();


		return services;
	}
}
