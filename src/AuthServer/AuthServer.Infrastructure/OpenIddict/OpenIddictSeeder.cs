using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;

namespace PixSmith.Authorization.Infrastructure.OpenIddict;

/// <summary>
/// Seeds default OAuth clients and scopes into OpenIddict on startup.
/// In production you'd manage this through the Admin dashboard instead.
/// </summary>
public sealed class OpenIddictSeeder(IServiceProvider serviceProvider, IConfiguration configuration) : IHostedService
{
	public async Task StartAsync(CancellationToken cancellationToken)
	{
		await using var scope = serviceProvider.CreateAsyncScope();

		var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
		var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
		var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole<Guid>>>();

		// ─── Seed Identity Roles ───────────────────────────────────────────

		await EnsureRoleAsync(roleManager, "Admin", cancellationToken);
		await EnsureRoleAsync(roleManager, "User", cancellationToken);

		// ─── Seed Scopes ───────────────────────────────────────────────────

		await EnsureScopeAsync(scopeManager, "api", "API Access", cancellationToken);
		await EnsureScopeAsync(scopeManager, "admin", "Admin Access", cancellationToken);

		// ─── Seed Blazor WASM Client (Public / PKCE + ROPC) ──────────────────

		var blazorClientId = configuration["OpenIddict:BlazorClient:ClientId"]
			?? throw new InvalidOperationException("OpenIddict:BlazorClient:ClientId is required.");
		var blazorBase = (configuration["OpenIddict:BlazorClient:BaseUri"] ?? "https://localhost:7100").TrimEnd('/');

		var blazorDescriptor = new OpenIddictApplicationDescriptor
		{
			ClientId = blazorClientId,
			ClientType = OpenIddictConstants.ClientTypes.Public,
			DisplayName = "Blazor WASM Client",
			RedirectUris =
			{
				new Uri($"{blazorBase}/authentication/login-callback"),
				new Uri($"{blazorBase}/signin-oidc"),
			},
			PostLogoutRedirectUris =
			{
				new Uri($"{blazorBase}/authentication/logout-callback"),
			},
			Permissions =
			{
				OpenIddictConstants.Permissions.Endpoints.Authorization,
				OpenIddictConstants.Permissions.Endpoints.Token,
				OpenIddictConstants.Permissions.Endpoints.EndSession,
				OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
				OpenIddictConstants.Permissions.GrantTypes.Password,
				OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
				OpenIddictConstants.Permissions.ResponseTypes.Code,
				OpenIddictConstants.Permissions.Scopes.Email,
				OpenIddictConstants.Permissions.Scopes.Profile,
				OpenIddictConstants.Permissions.Scopes.Roles,
				OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.OfflineAccess,
				"scp:api",
				"scp:admin",
			},
			Requirements =
			{
				OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange,
			}
		};

		var blazorClient = await manager.FindByClientIdAsync(blazorClientId, cancellationToken);
		if (blazorClient is null)
			await manager.CreateAsync(blazorDescriptor, cancellationToken);
		else
			await manager.UpdateAsync(blazorClient, blazorDescriptor, cancellationToken);

		// ─── Seed Machine-to-Machine (M2M) Client ──────────────────────────

		var m2mClientId = configuration["OpenIddict:M2MClient:ClientId"]
			?? throw new InvalidOperationException("OpenIddict:M2MClient:ClientId is required.");
		var m2mSecret = configuration["OpenIddict:M2MClient:ClientSecret"]
			?? throw new InvalidOperationException("OpenIddict:M2MClient:ClientSecret is required.");

		if (await manager.FindByClientIdAsync(m2mClientId, cancellationToken) is null)
		{
			await manager.CreateAsync(new OpenIddictApplicationDescriptor
			{
				ClientId = m2mClientId,
				ClientSecret = m2mSecret,
				ClientType = OpenIddictConstants.ClientTypes.Confidential,
				DisplayName = "Machine-to-Machine Client",
				Permissions =
				{
					OpenIddictConstants.Permissions.Endpoints.Token,
					OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
					"scp:api",
				}
			}, cancellationToken);
		}
	}

	public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

	private static async Task EnsureRoleAsync(
		RoleManager<IdentityRole<Guid>> roleManager,
		string name,
		CancellationToken ct)
	{
		if (!await roleManager.RoleExistsAsync(name))
			await roleManager.CreateAsync(new IdentityRole<Guid>(name));
	}

	private static async Task EnsureScopeAsync(
		IOpenIddictScopeManager manager,
		string name,
		string displayName,
		CancellationToken ct)
	{
		if (await manager.FindByNameAsync(name, ct) is null)
		{
			await manager.CreateAsync(new OpenIddictScopeDescriptor
			{
				Name = name,
				DisplayName = displayName,
				Resources = { "resource-server" }
			}, ct);
		}
	}
}
