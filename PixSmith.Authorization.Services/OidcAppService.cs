using OpenIddict.Abstractions;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Domain.Results;
using PixSmith.Authorization.Services.Interfaces;

namespace PixSmith.Authorization.Services;

public sealed class OidcAppService(IOpenIddictApplicationManager manager) : IOidcAppService
{
    public async Task<Result<IReadOnlyList<OidcAppDto>>> GetAllAsync(CancellationToken ct = default)
    {
        try
        {
            var apps = new List<OidcAppDto>();
            await foreach (var app in manager.ListAsync(cancellationToken: ct))
                apps.Add(await ToDtoAsync(app, ct));
            return Result<IReadOnlyList<OidcAppDto>>.Success(apps);
        }
        catch (Exception ex)
        {
            return Result<IReadOnlyList<OidcAppDto>>.Failure(ex.Message);
        }
    }

    public async Task<Result<OidcAppDto>> GetByClientIdAsync(string clientId, CancellationToken ct = default)
    {
        var app = await manager.FindByClientIdAsync(clientId, ct);
        if (app is null) return Result<OidcAppDto>.Failure("Application not found.");
        return Result<OidcAppDto>.Success(await ToDtoAsync(app, ct));
    }

    public async Task<Result<OidcAppDto>> CreateAsync(CreateOidcAppRequest request, CancellationToken ct = default)
    {
        try
        {
            if (await manager.FindByClientIdAsync(request.ClientId, ct) is not null)
                return Result<OidcAppDto>.Failure($"An application with client ID '{request.ClientId}' already exists.");

            var descriptor = BuildDescriptor(
                request.ClientId, request.ClientSecret, request.DisplayName, request.ClientType,
                request.RedirectUris, request.PostLogoutRedirectUris, request.Scopes, request.GrantTypes);

            var app = await manager.CreateAsync(descriptor, ct);
            return Result<OidcAppDto>.Success(await ToDtoAsync(app, ct));
        }
        catch (Exception ex)
        {
            return Result<OidcAppDto>.Failure(ex.Message);
        }
    }

    public async Task<Result> UpdateAsync(string clientId, UpdateOidcAppRequest request, CancellationToken ct = default)
    {
        var app = await manager.FindByClientIdAsync(clientId, ct);
        if (app is null) return Result.Failure("Application not found.");

        try
        {
            var existing = await manager.GetClientTypeAsync(app, ct) ?? OpenIddictConstants.ClientTypes.Public;
            var descriptor = BuildDescriptor(
                clientId, null, request.DisplayName, existing,
                request.RedirectUris, request.PostLogoutRedirectUris, request.Scopes, request.GrantTypes);

            await manager.UpdateAsync(app, descriptor, ct);
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(ex.Message);
        }
    }

    public async Task<Result> DeleteAsync(string clientId, CancellationToken ct = default)
    {
        var app = await manager.FindByClientIdAsync(clientId, ct);
        if (app is null) return Result.Failure("Application not found.");

        try
        {
            await manager.DeleteAsync(app, ct);
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(ex.Message);
        }
    }

    private async Task<OidcAppDto> ToDtoAsync(object app, CancellationToken ct)
    {
        var clientId = await manager.GetClientIdAsync(app, ct) ?? string.Empty;
        var displayName = await manager.GetDisplayNameAsync(app, ct);
        var clientType = await manager.GetClientTypeAsync(app, ct) ?? OpenIddictConstants.ClientTypes.Public;
        var permissions = (await manager.GetPermissionsAsync(app, ct)).ToList();
        var redirectUris = (await manager.GetRedirectUrisAsync(app, ct)).Select(u => u.ToString()).ToList();
        var postLogoutUris = (await manager.GetPostLogoutRedirectUrisAsync(app, ct)).Select(u => u.ToString()).ToList();
        var requirements = (await manager.GetRequirementsAsync(app, ct)).ToList();

        return new OidcAppDto(clientId, displayName, clientType, redirectUris, postLogoutUris, permissions, requirements);
    }

    private static OpenIddictApplicationDescriptor BuildDescriptor(
        string clientId, string? clientSecret, string? displayName, string clientType,
        List<string> redirectUris, List<string> postLogoutUris,
        List<string> scopes, List<string> grantTypes)
    {
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
            DisplayName = displayName,
            ClientType = clientType,
        };

        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);

        if (grantTypes.Contains("authorization_code") || grantTypes.Contains("password"))
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Authorization);

        if (redirectUris.Count > 0 || grantTypes.Contains("authorization_code"))
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.EndSession);

        foreach (var grant in grantTypes)
        {
            descriptor.Permissions.Add(grant switch
            {
                "authorization_code" => OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                "client_credentials" => OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                "password" => OpenIddictConstants.Permissions.GrantTypes.Password,
                "refresh_token" => OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                _ => OpenIddictConstants.Permissions.Prefixes.GrantType + grant,
            });
        }

        if (grantTypes.Contains("authorization_code"))
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.ResponseTypes.Code);

        foreach (var scope in scopes)
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + scope);

        foreach (var uri in redirectUris)
            descriptor.RedirectUris.Add(new Uri(uri));

        foreach (var uri in postLogoutUris)
            descriptor.PostLogoutRedirectUris.Add(new Uri(uri));

        if (clientType == OpenIddictConstants.ClientTypes.Public && grantTypes.Contains("authorization_code"))
            descriptor.Requirements.Add(OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange);

        return descriptor;
    }
}
