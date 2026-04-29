using AuthServer.Infrastructure.OpenIddict;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Validation.AspNetCore;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Repositories;
using PixSmith.Authorization.Repositories.Interfaces;
using PixSmith.Authorization.Services;
using PixSmith.Authorization.Services.Interfaces;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthServer.API;

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
					   .SetUserinfoEndpointUris("/connect/userinfo")
					   .SetLogoutEndpointUris("/connect/logout")
					   .SetIntrospectionEndpointUris("/connect/introspect")
					   .SetRevocationEndpointUris("/connect/revoke")
					   .SetCryptographyEndpointUris("/.well-known/jwks");

				// Supported flows
				options.AllowAuthorizationCodeFlow()
					   .AllowClientCredentialsFlow()
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
					.EnableUserinfoEndpointPassthrough()
					.EnableLogoutEndpointPassthrough()
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

		// ─── Repositories ───────────────────────────────────────

		services.AddTransient<IOAuthClientRepository, OAuthClientRepository>();

		services.AddTransient<IUserRepository, UserRepository>();

		// ─── Services ───────────────────────────────────────

		services.AddTransient<IPasswordHashingService, PasswordHashingService>();

		services.AddTransient<IUserService, UserService>();

		services.AddTransient<IEmailService, EmailService>();

		services.AddTransient<IOAuthClientService, OAuthClientService>();

		services.AddHostedService<OpenIddictSeeder>();


		return services;
	}
}
