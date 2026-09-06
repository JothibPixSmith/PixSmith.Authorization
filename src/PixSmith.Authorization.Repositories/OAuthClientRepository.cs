using PixSmith.Authorization.Domain.Entities;
using PixSmith.Authorization.Domain.Enums;
using Microsoft.EntityFrameworkCore;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Repositories.Interfaces;
using System.Text.Json;

namespace PixSmith.Authorization.Repositories;

public sealed class OAuthClientRepository(ApplicationDbContext context) : IOAuthClientRepository
{
    public async Task<OAuthClient?> GetByIdAsync(Guid id, CancellationToken ct = default)
    {
        var reg = await context.OAuthClientRegistrations.FindAsync([id], ct);
        return reg is null ? null : ToClient(reg);
    }

    public async Task<OAuthClient?> GetByClientIdAsync(string clientId, CancellationToken ct = default)
    {
        var reg = await context.OAuthClientRegistrations
            .FirstOrDefaultAsync(c => c.ClientId == clientId, ct);
        return reg is null ? null : ToClient(reg);
    }

    public async Task<IEnumerable<OAuthClient>> GetAllAsync(CancellationToken ct = default)
    {
        var registrations = await context.OAuthClientRegistrations
            .OrderBy(c => c.DisplayName)
            .ToListAsync(ct);
        return registrations.Select(ToClient);
    }

    public async Task AddAsync(OAuthClient client, CancellationToken ct = default)
    {
        context.OAuthClientRegistrations.Add(ToRegistration(client));
        await context.SaveChangesAsync(ct);
    }

    public async Task UpdateAsync(OAuthClient client, CancellationToken ct = default)
    {
        var reg = await context.OAuthClientRegistrations.FindAsync([client.Id], ct);
        if (reg is null) return;

        ApplyChanges(client, reg);
        await context.SaveChangesAsync(ct);
    }

    public async Task DeleteAsync(Guid id, CancellationToken ct = default)
    {
        var reg = await context.OAuthClientRegistrations.FindAsync([id], ct);
        if (reg is null) return;

        context.OAuthClientRegistrations.Remove(reg);
        await context.SaveChangesAsync(ct);
    }

    // ── Mapping ───────────────────────────────────────────────────────────────

    private static OAuthClient ToClient(OAuthClientRegistration reg) =>
        OAuthClient.Reconstitute(
            id:                                    reg.Id,
            clientId:                              reg.ClientId,
            clientSecret:                          reg.ClientSecret,
            displayName:                           reg.DisplayName,
            description:                           reg.Description,
            logoUri:                               reg.LogoUri,
            clientType:                            Enum.Parse<ClientType>(reg.ClientType, ignoreCase: true),
            isActive:                              reg.IsActive,
            requireConsent:                        reg.RequireConsent,
            requirePkce:                           reg.RequirePkce,
            allowOfflineAccess:                    reg.AllowOfflineAccess,
            accessTokenLifetimeSeconds:            reg.AccessTokenLifetimeSeconds,
            identityTokenLifetimeSeconds:          reg.IdentityTokenLifetimeSeconds,
            absoluteRefreshTokenLifetimeSeconds:   reg.AbsoluteRefreshTokenLifetimeSeconds,
            createdAt:                             reg.CreatedAt,
            createdByUserId:                       reg.CreatedByUserId,
            redirectUris:                          Deserialize(reg.RedirectUrisJson),
            allowedScopes:                         Deserialize(reg.AllowedScopesJson),
            allowedGrantTypes:                     Deserialize(reg.AllowedGrantTypesJson),
            corsOrigins:                           Deserialize(reg.CorsOriginsJson));

    private static OAuthClientRegistration ToRegistration(OAuthClient client) => new()
    {
        Id                                  = client.Id,
        ClientId                            = client.ClientId,
        ClientSecret                        = client.ClientSecret,
        DisplayName                         = client.DisplayName,
        Description                         = client.Description,
        LogoUri                             = client.LogoUri,
        ClientType                          = client.ClientType.ToString(),
        IsActive                            = client.IsActive,
        RequireConsent                      = client.RequireConsent,
        RequirePkce                         = client.RequirePkce,
        AllowOfflineAccess                  = client.AllowOfflineAccess,
        AccessTokenLifetimeSeconds          = client.AccessTokenLifetimeSeconds,
        IdentityTokenLifetimeSeconds        = client.IdentityTokenLifetimeSeconds,
        AbsoluteRefreshTokenLifetimeSeconds = client.AbsoluteRefreshTokenLifetimeSeconds,
        CreatedAt                           = client.CreatedAt,
        CreatedByUserId                     = client.CreatedByUserId,
        RedirectUrisJson                    = Serialize(client.RedirectUris),
        AllowedScopesJson                   = Serialize(client.AllowedScopes),
        AllowedGrantTypesJson               = Serialize(client.AllowedGrantTypes),
        CorsOriginsJson                     = Serialize(client.CorsOrigins),
    };

    private static void ApplyChanges(OAuthClient client, OAuthClientRegistration reg)
    {
        reg.ClientSecret                        = client.ClientSecret;
        reg.DisplayName                         = client.DisplayName;
        reg.Description                         = client.Description;
        reg.LogoUri                             = client.LogoUri;
        reg.ClientType                          = client.ClientType.ToString();
        reg.IsActive                            = client.IsActive;
        reg.RequireConsent                      = client.RequireConsent;
        reg.RequirePkce                         = client.RequirePkce;
        reg.AllowOfflineAccess                  = client.AllowOfflineAccess;
        reg.AccessTokenLifetimeSeconds          = client.AccessTokenLifetimeSeconds;
        reg.IdentityTokenLifetimeSeconds        = client.IdentityTokenLifetimeSeconds;
        reg.AbsoluteRefreshTokenLifetimeSeconds = client.AbsoluteRefreshTokenLifetimeSeconds;
        reg.RedirectUrisJson                    = Serialize(client.RedirectUris);
        reg.AllowedScopesJson                   = Serialize(client.AllowedScopes);
        reg.AllowedGrantTypesJson               = Serialize(client.AllowedGrantTypes);
        reg.CorsOriginsJson                     = Serialize(client.CorsOrigins);
    }

    private static List<string> Deserialize(string json) =>
        JsonSerializer.Deserialize<List<string>>(json) ?? [];

    private static string Serialize(IEnumerable<string> values) =>
        JsonSerializer.Serialize(values);
}
