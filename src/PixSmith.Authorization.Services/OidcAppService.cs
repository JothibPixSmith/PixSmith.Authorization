using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using PixSmith.Authorization.Infrastructure.OpenIddict;
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
    IConfiguration configuration,
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

            var grants = CheckGrantTypes(request.GrantTypes);
            if (!grants.IsSuccess) return Result<OidcAppDto>.Failure(grants.Error!);

            var exemption = CheckPkceExemption(request.PkceExempt, request.ClientType, request.GrantTypes);
            if (!exemption.IsSuccess) return Result<OidcAppDto>.Failure(exemption.Error!);

            var introspection = CheckIntrospection(request.AllowIntrospection, request.ClientType);
            if (!introspection.IsSuccess) return Result<OidcAppDto>.Failure(introspection.Error!);

            var descriptor = BuildDescriptor(
                request.ClientId, request.ClientSecret, request.DisplayName, request.ClientType,
                request.RedirectUris, request.PostLogoutRedirectUris, request.Scopes, request.GrantTypes,
                request.PkceExempt, request.AllowIntrospection);

            if (!string.IsNullOrWhiteSpace(request.JsonWebKeySet))
            {
                var keys = ApplyKeySet(descriptor, request.JsonWebKeySet, request.ClientType);
                if (!keys.IsSuccess) return Result<OidcAppDto>.Failure(keys.Error!);
            }

            var app = await manager.CreateAsync(descriptor, ct);
            if (request.PkceExempt) await RecordExemptionAsync(request.ClientId, ct);
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

            // Not "keep what is there": an update that omits the flag puts PKCE back. Losing an
            // exemption by accident is safe; keeping one by accident is not.
            var grants = CheckGrantTypes(request.GrantTypes);
            if (!grants.IsSuccess) return Result.Failure(grants.Error!);

            var exemption = CheckPkceExemption(request.PkceExempt, existing, request.GrantTypes);
            if (!exemption.IsSuccess) return Result.Failure(exemption.Error!);

            var introspection = CheckIntrospection(request.AllowIntrospection, existing);
            if (!introspection.IsSuccess) return Result.Failure(introspection.Error!);

            var descriptor = BuildDescriptor(
                clientId, preservedSecret, request.DisplayName, existing,
                request.RedirectUris, request.PostLogoutRedirectUris, request.Scopes, request.GrantTypes,
                request.PkceExempt, request.AllowIntrospection);

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
            if (request.PkceExempt && !PkcePolicy.IsFlaggedExempt(current.Settings))
                await RecordExemptionAsync(clientId, ct);
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(ex.Message);
        }
    }

    /// <summary>
    /// Refuses grant types the server does not support.
    ///
    /// <para>
    /// The password grant in particular: the server removed it server-wide, but an admin could
    /// still create a client carrying <c>gt:password</c>. That client would look configured and
    /// do nothing — and would quietly start working if the grant were ever re-enabled, which is
    /// the opposite of what removing it was for. Refusing it here says so plainly instead of
    /// silently dropping the permission.
    /// </para>
    /// </summary>
    private static Result CheckGrantTypes(List<string> grantTypes)
    {
        var password = grantTypes.FirstOrDefault(g =>
            g is "password" or "urn:ietf:params:oauth:grant-type:password");

        if (password is not null)
        {
            return Result.Failure(
                "The resource owner password credentials grant is not supported by this server. " +
                "Use authorization_code with PKCE for interactive clients, client_credentials " +
                "for machine-to-machine callers, or the device authorization grant " +
                "(urn:ietf:params:oauth:grant-type:device_code) for a device or CLI that needs " +
                "a user's token.");
        }

        return Result.Success();
    }

    /// <summary>
    /// A PKCE exemption is refused unless the server allows them, and only ever granted to a
    /// confidential authorization-code client: a public client has nothing else protecting
    /// its codes, and an exemption on a client without the code grant would mean nothing.
    /// </summary>
    private Result CheckPkceExemption(bool requested, string clientType, List<string> grantTypes)
    {
        if (!requested) return Result.Success();

        if (!PkcePolicy.ExemptionsAllowed(configuration))
        {
            return Result.Failure(
                $"PKCE exemptions are disabled on this server ({PkcePolicy.AllowExemptClientsKey} is not true). " +
                "They exist only for conformance-test runs against non-production servers.");
        }

        if (!string.Equals(clientType, OpenIddictConstants.ClientTypes.Confidential, StringComparison.OrdinalIgnoreCase))
            return Result.Failure("Only a confidential client can be exempted from PKCE.");

        if (!grantTypes.Contains("authorization_code"))
            return Result.Failure("A PKCE exemption only applies to a client using the authorization_code grant.");

        return Result.Success();
    }

    private async Task RecordExemptionAsync(string clientId, CancellationToken ct)
    {
        logger.LogWarning(
            "OIDC application {ClientId} is exempt from PKCE. Delete it after the test run.", clientId);
        await audit.RecordAsync("oidc-app.pkce.exempted",
            $"Client '{clientId}' may use the authorization code grant without PKCE.", ct);
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
            permissions, requirements, signingKeys,
            PkceExempt: PkcePolicy.UsesAuthorizationCode(permissions)
                && !requirements.Contains(OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange));
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

    /// <summary>
    /// Refuses introspection for a public client rather than granting a permission that cannot
    /// work. The introspection endpoint authenticates the caller — a client with no credentials
    /// has nothing to authenticate with, so the grant would look configured and fail at the
    /// endpoint. Said plainly here instead, for the same reason the password grant is.
    /// </summary>
    private static Result CheckIntrospection(bool allowIntrospection, string clientType)
    {
        if (!allowIntrospection) return Result.Success();

        if (!string.Equals(clientType, OpenIddictConstants.ClientTypes.Confidential,
                StringComparison.OrdinalIgnoreCase))
        {
            return Result.Failure(
                "Introspection requires a confidential client: the introspection endpoint "
                + "authenticates the caller, and a public client has no credentials to "
                + "authenticate with. Revocation is granted to every client and needs no flag.");
        }

        return Result.Success();
    }

    /// <summary>
    /// Matches the device authorization grant by either its RFC 8628 URN or the short
    /// "device_code" alias.
    /// </summary>
    private static bool IsDeviceCodeGrant(string grant) =>
        grant is "device_code" or "urn:ietf:params:oauth:grant-type:device_code";

    private static OpenIddictApplicationDescriptor BuildDescriptor(
        string clientId, string? clientSecret, string? displayName, string clientType,
        List<string> redirectUris, List<string> postLogoutUris,
        List<string> scopes, List<string> grantTypes, bool pkceExempt,
        bool allowIntrospection)
    {
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
            DisplayName = displayName,
            ClientType = clientType,
        };

        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);

        // ── CR-7 ────────────────────────────────────────────────────────────
        // Revocation, for every client. Without it no client created through the admin API
        // could revoke its own tokens at logout (RFC 7009), so a user's refresh token outlived
        // their logout — and a refresh token is the credential that can be exchanged for new
        // access tokens for as long as it lives. Public clients get it too, which RFC 7009 §2.1
        // allows: OpenIddict validates the token's presenters, so a client can only ever revoke
        // a token that was issued to it.
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Revocation);

        // Introspection is the other direction — asking about tokens the caller did not
        // present — and belongs to resource servers, so it is opt-in. CheckIntrospection has
        // already refused it for public clients.
        if (allowIntrospection)
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Introspection);

        if (grantTypes.Contains("authorization_code"))
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Authorization);

        // ── CR-1 ────────────────────────────────────────────────────────────
        // The device grant needs the device authorization endpoint as well as the grant
        // itself. Without this a client created through the admin API carries gt:…device_code
        // but is refused at /connect/deviceauthorization, so only the seeded provisioning-cli
        // ever worked.
        if (grantTypes.Any(IsDeviceCodeGrant))
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.DeviceAuthorization);

        if (redirectUris.Count > 0 || grantTypes.Contains("authorization_code"))
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.EndSession);

        foreach (var grant in grantTypes)
        {
            descriptor.Permissions.Add(grant switch
            {
                "authorization_code" => OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                "client_credentials" => OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                "refresh_token" => OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                // Accepts the short alias as well as the URN, since the URN is awkward to type
                // and a caller sending "device_code" would otherwise get a permission the
                // server never matches.
                _ when IsDeviceCodeGrant(grant)
                    => OpenIddictConstants.Permissions.GrantTypes.DeviceCode,
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

        // Every authorization-code client, public or confidential (ASVS 5.0 10.4.6). Enforced
        // per client since the server-wide switch was removed; see PkcePolicy. The exemption
        // has already been validated by CheckPkceExemption.
        if (grantTypes.Contains("authorization_code"))
        {
            if (pkceExempt)
                descriptor.Settings[PkcePolicy.ExemptSetting] = "true";
            else
                descriptor.Requirements.Add(OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange);
        }

        return descriptor;
    }
}
