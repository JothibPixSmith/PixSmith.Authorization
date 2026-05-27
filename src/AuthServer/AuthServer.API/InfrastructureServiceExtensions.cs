using PixSmith.Authorization.Infrastructure.OpenIddict;
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
		IConfiguration configuration)
	{
		// ─── EF Core ───────────────────────────────────────────────────────

		var connectionString = configuration.GetConnectionString("DefaultConnection")
			?? "Data Source=auth.db";

		services.AddDbContext<ApplicationDbContext>(options =>
		{
			options.UseSqlite(connectionString);

			// Register EF Core entity sets for OpenIddict (uses Guid PKs)
			options.UseOpenIddict<Guid>();
		});

		// ─── ASP.NET Identity ──────────────────────────────────────────────

		services.AddIdentity<IdentityUser<Guid>, IdentityRole<Guid>>(options =>
		{
			options.Password.RequiredLength = 8;
			options.Password.RequireDigit = true;
			options.Password.RequireUppercase = true;
			options.Password.RequireNonAlphanumeric = true;
			options.Lockout.MaxFailedAccessAttempts = 5;
			options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
			options.User.RequireUniqueEmail = true;
			options.SignIn.RequireConfirmedEmail = false; // set true in production
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

				// Dev encryption/signing (replace with proper certs in production)
				options.AddDevelopmentEncryptionCertificate()
					   .AddDevelopmentSigningCertificate();

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
			options.AddPolicy("AdminAccess", policy =>
			{
				policy.AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
				policy.RequireAuthenticatedUser();
				policy.RequireAssertion(ctx =>
					ctx.User.IsInRole("Admin") ||
					ctx.User.HasClaim(Claims.Private.Scope, "admin"));
			});
		});

		// ─── CORS ───────────────────────────────────────────────────────────

		var blazorOrigin = configuration["AllowedOrigins:BlazorClient"] ?? "https://localhost:7200";
		services.AddCors(options =>
			options.AddDefaultPolicy(policy =>
				policy
					.WithOrigins(blazorOrigin)
					.AllowAnyHeader()
					.AllowAnyMethod()));

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

		// ─── Services ───────────────────────────────────────

		services.AddTransient<IPasswordHashingService, PasswordHashingService>();
		services.AddTransient<IEmailService, EmailService>();

		services.AddTransient<IUserService, UserService>();
		services.AddTransient<IAccountService, AccountService>();
		services.AddTransient<IAdminService, AdminService>();
		services.AddTransient<IConnectService, ConnectService>();
		services.AddTransient<IOAuthClientService, OAuthClientService>();

		services.AddHostedService<OpenIddictSeeder>();


		return services;
	}
}
