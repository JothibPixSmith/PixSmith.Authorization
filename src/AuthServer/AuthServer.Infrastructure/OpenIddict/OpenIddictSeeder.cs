using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;

namespace PixSmith.Authorization.Infrastructure.OpenIddict;

/// <summary>
/// Seeds default OAuth clients and scopes into OpenIddict on startup.
/// In production you'd manage this through the Admin dashboard instead.
/// </summary>
public sealed class OpenIddictSeeder(IServiceProvider serviceProvider) : IHostedService
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
		// Upsert so existing databases pick up any permission changes on restart.

		var blazorDescriptor = new OpenIddictApplicationDescriptor
		{
			ClientId = "blazor-client",
			ClientType = OpenIddictConstants.ClientTypes.Public,
			DisplayName = "Blazor WASM Client",
			RedirectUris =
			{
				new Uri("https://localhost:7200/authentication/login-callback"),
				new Uri("https://localhost:7200/signin-oidc"),
			},
			PostLogoutRedirectUris =
			{
				new Uri("https://localhost:7200/authentication/logout-callback"),
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

		var blazorClient = await manager.FindByClientIdAsync("blazor-client", cancellationToken);
		if (blazorClient is null)
			await manager.CreateAsync(blazorDescriptor, cancellationToken);
		else
			await manager.UpdateAsync(blazorClient, blazorDescriptor, cancellationToken);

		// ─── Seed Machine-to-Machine (M2M) Client ──────────────────────────

		if (await manager.FindByClientIdAsync("m2m-client", cancellationToken) is null)
		{
			await manager.CreateAsync(new OpenIddictApplicationDescriptor
			{
				ClientId = "m2m-client",
				ClientSecret = "m2m-super-secret-change-in-production",
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
