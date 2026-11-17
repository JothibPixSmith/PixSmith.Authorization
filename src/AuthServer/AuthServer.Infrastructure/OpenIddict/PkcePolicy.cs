using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PixSmith.Authorization.Infrastructure.OpenIddict;

/// <summary>
/// PKCE is required per client, on every client that may use the authorization code grant.
///
/// <para>
/// It used to be a server-wide switch. Per-client is the same protection for every normal
/// client and makes room for exactly one narrow exception: a client flagged
/// <see cref="ExemptSetting"/>, honoured only while <see cref="AllowExemptClientsKey"/> is
/// true. That exists for test suites (e.g. the OpenID Foundation conformance suite) whose
/// certification plans send no code_challenge. It is off by default and the server refuses
/// to start with it on in Production.
/// </para>
///
/// <para>
/// With the setting off the flag is ignored: <see cref="EnforceAsync"/> runs at startup and
/// puts the requirement back on every authorization-code client, flagged or not. So turning
/// the setting off and restarting is enough to close any exemption.
/// </para>
///
/// <para>
/// The <c>plain</c> method is disabled server-wide regardless (see the OpenIddict server
/// options); an exempt client may send no challenge, never a weak one. ASVS 5.0 10.4.6.
/// </para>
/// </summary>
public static class PkcePolicy
{
    public const string AllowExemptClientsKey = "Security:AllowPkceExemptClients";

    /// <summary>Stored in the OpenIddict application's Settings; value "true".</summary>
    public const string ExemptSetting = "pixsmith:pkce_exempt";

    public static bool ExemptionsAllowed(IConfiguration configuration) =>
        configuration.GetValue<bool>(AllowExemptClientsKey);

    /// <summary>Called at startup. Exemptions are a test-suite convenience, never production.</summary>
    public static void ValidateConfiguration(IConfiguration configuration, IHostEnvironment environment)
    {
        if (ExemptionsAllowed(configuration) && environment.IsProduction())
        {
            throw new InvalidOperationException(
                $"{AllowExemptClientsKey} is true and the environment is Production. PKCE exemptions " +
                "exist only for conformance-test runs against non-production servers. Remove the setting.");
        }
    }

    public static bool UsesAuthorizationCode(IEnumerable<string> permissions) =>
        permissions.Contains(Permissions.GrantTypes.AuthorizationCode);

    public static bool IsFlaggedExempt(IReadOnlyDictionary<string, string> settings) =>
        settings.TryGetValue(ExemptSetting, out var value)
        && string.Equals(value, "true", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Puts the PKCE requirement on every authorization-code client that lacks it, except a
    /// flagged one while exemptions are allowed. Idempotent. Returns the client ids changed.
    /// </summary>
    public static async Task<IReadOnlyList<string>> EnforceAsync(
        IOpenIddictApplicationManager manager, bool exemptionsAllowed, CancellationToken ct = default)
    {
        var changed = new List<string>();

        // Materialised first: updating while the store's query is still being enumerated is
        // not safe on every provider.
        var apps = new List<object>();
        await foreach (var app in manager.ListAsync(cancellationToken: ct)) apps.Add(app);

        foreach (var app in apps)
        {
            var descriptor = new OpenIddictApplicationDescriptor();
            await manager.PopulateAsync(descriptor, app, ct);

            if (!UsesAuthorizationCode(descriptor.Permissions)) continue;
            if (descriptor.Requirements.Contains(Requirements.Features.ProofKeyForCodeExchange)) continue;
            if (exemptionsAllowed && IsFlaggedExempt(descriptor.Settings)) continue;

            // PopulateAsync hands back the stored secret hash, and OpenIddict only re-hashes a
            // secret that differs from what is stored, so the secret survives this update.
            descriptor.Requirements.Add(Requirements.Features.ProofKeyForCodeExchange);
            await manager.UpdateAsync(app, descriptor, ct);
            changed.Add(descriptor.ClientId ?? "(no client id)");
        }

        return changed;
    }
}
