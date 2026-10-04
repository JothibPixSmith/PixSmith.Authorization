using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using System.Security.Cryptography;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Domain.Results;
using PixSmith.Authorization.Repositories.Interfaces;
using PixSmith.Authorization.Services.Interfaces;

namespace PixSmith.Authorization.Services;

public sealed class OidcAppService(
    IOpenIddictApplicationManager manager,
    ITenantApplicationRepository subscriptions,
    IAuditService audit,
    ILogger<OidcAppService> logger) : IOidcAppService
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

            if (!string.IsNullOrWhiteSpace(request.JsonWebKeySet))
            {
                var keys = ApplyKeySet(descriptor, request.JsonWebKeySet, request.ClientType);
                if (!keys.IsSuccess) return Result<OidcAppDto>.Failure(keys.Error!);
            }

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

            // Carry the stored secret through untouched. Passing null here fails validation
            // outright for confidential applications ("the client secret cannot be null or
            // empty"), which made them impossible to edit at all.
            //
            // OpenIddict stores the secret hashed and will not return the plaintext, but it
            // compares the descriptor's value against what is stored and only re-hashes when
            // they differ — so handing the stored hash straight back is a no-op, and the
            // secret survives the update. Changing it is RotateSecretAsync's job.
            //
            // PopulateAsync fills a descriptor *from* the stored application, which is the
            // only route to the hash through IOpenIddictApplicationManager.
            var current = new OpenIddictApplicationDescriptor();
            await manager.PopulateAsync(current, app, ct);
            var preservedSecret = current.ClientSecret;

            var descriptor = BuildDescriptor(
                clientId, preservedSecret, request.DisplayName, existing,
                request.RedirectUris, request.PostLogoutRedirectUris, request.Scopes, request.GrantTypes);

            // Public keys, unlike the secret, really can be read back — so "omitted means keep
            // what is registered" is honestly implementable here rather than a polite fiction.
            if (string.IsNullOrWhiteSpace(request.JsonWebKeySet))
            {
                descriptor.JsonWebKeySet = current.JsonWebKeySet;
            }
            else
            {
                var keys = ApplyKeySet(descriptor, request.JsonWebKeySet, existing);
                if (!keys.IsSuccess) return Result.Failure(keys.Error!);
            }

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

            // Subscriptions reference the client by value rather than by foreign key, so
            // deleting the client would otherwise leave rows behind — and a later client
            // registered with the same id would silently inherit every one of them.
            var orphaned = (await subscriptions.GetForClientAsync(clientId, ct)).ToList();
            foreach (var subscription in orphaned)
                await subscriptions.DeleteAsync(subscription.Id, ct);

            if (orphaned.Count > 0)
            {
                await audit.RecordAsync("oidc-app.deleted",
                    $"Client '{clientId}' deleted; removed {orphaned.Count} company subscription(s).", ct);
            }

            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(ex.Message);
        }
    }

    public async Task<Result<RotateClientSecretResponse>> RotateSecretAsync(
        string clientId, RotateClientSecretRequest request, CancellationToken ct = default)
    {
        var app = await manager.FindByClientIdAsync(clientId, ct);
        if (app is null)
            return Result<RotateClientSecretResponse>.Failure("Application not found.");

        var clientType = await manager.GetClientTypeAsync(app, ct)
            ?? OpenIddictConstants.ClientTypes.Public;

        // A public client must not hold a secret — it cannot keep one — and OpenIddict
        // rejects the combination. Say so plainly rather than surfacing its validation text.
        if (!string.Equals(clientType, OpenIddictConstants.ClientTypes.Confidential,
                StringComparison.OrdinalIgnoreCase))
        {
            await audit.RecordAsync(
                "oidc-app.secret.rotation-refused",
                $"Client '{clientId}' is a {clientType} application and has no client secret.", ct);

            return Result<RotateClientSecretResponse>.Failure(
                $"Client '{clientId}' is a {clientType} application and has no client secret to rotate.");
        }

        var secret = string.IsNullOrWhiteSpace(request.ClientSecret)
            ? GenerateSecret()
            : request.ClientSecret;

        try
        {
            // This overload hashes the value before persisting it.
            await manager.UpdateAsync(app, secret, ct);

            logger.LogWarning(
                "Client secret rotated for OIDC application {ClientId}. Every deployment using " +
                "the previous secret will fail to authenticate until it is updated.", clientId);

            // Recorded after the rotation, never before: an entry claiming a rotation that then
            // failed would be worse than no entry. The secret itself is deliberately absent —
            // the audit table is readable by every admin.
            await audit.RecordAsync(
                "oidc-app.secret.rotated",
                $"Client '{clientId}' ({clientType}); secret was " +
                (string.IsNullOrWhiteSpace(request.ClientSecret) ? "generated." : "supplied by the caller."),
                ct);

            return Result<RotateClientSecretResponse>.Success(
                new RotateClientSecretResponse(clientId, secret));
        }
        catch (Exception ex)
        {
            return Result<RotateClientSecretResponse>.Failure(ex.Message);
        }
    }

    /// <summary>
    /// 256 bits from a cryptographic RNG, base64url-encoded so it survives env vars,
    /// connection strings and YAML without escaping.
    /// </summary>
    private static string GenerateSecret() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');

    private async Task<OidcAppDto> ToDtoAsync(object app, CancellationToken ct)
    {
        var clientId = await manager.GetClientIdAsync(app, ct) ?? string.Empty;
        var displayName = await manager.GetDisplayNameAsync(app, ct);
        var clientType = await manager.GetClientTypeAsync(app, ct) ?? OpenIddictConstants.ClientTypes.Public;
        var permissions = (await manager.GetPermissionsAsync(app, ct)).ToList();
        var redirectUris = (await manager.GetRedirectUrisAsync(app, ct)).Select(u => u.ToString()).ToList();
        var postLogoutUris = (await manager.GetPostLogoutRedirectUrisAsync(app, ct)).Select(u => u.ToString()).ToList();
        var requirements = (await manager.GetRequirementsAsync(app, ct)).ToList();

        // PopulateAsync is the only route to the stored JWKS through the manager interface.
        var descriptor = new OpenIddictApplicationDescriptor();
        await manager.PopulateAsync(descriptor, app, ct);

        var signingKeys = descriptor.JsonWebKeySet?.Keys
            .Select(k => new OidcAppSigningKeyDto(k.Kid, k.Kty, k.Alg, k.Use))
            .ToList() ?? [];

        return new OidcAppDto(clientId, displayName, clientType, redirectUris, postLogoutUris,
            permissions, requirements, signingKeys);
    }

    /// <summary>
    /// Validates a JWKS and attaches it to the descriptor. Refused for public clients: a public
    /// client cannot keep a private key either, so registering one would imply a confidentiality
    /// guarantee that does not exist.
    /// </summary>
    private static Result ApplyKeySet(
        OpenIddictApplicationDescriptor descriptor, string json, string clientType)
    {
        if (!string.Equals(clientType, OpenIddictConstants.ClientTypes.Confidential,
                StringComparison.OrdinalIgnoreCase))
        {
            return Result.Failure(
                "A JSON Web Key Set can only be registered for a confidential application. " +
                "Public clients authenticate with PKCE and hold no credential.");
        }

        var validated = JsonWebKeySetValidator.Validate(json);
        if (!validated.IsSuccess) return Result.Failure(validated.Error!);

        descriptor.JsonWebKeySet = validated.Value;
        return Result.Success();
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
