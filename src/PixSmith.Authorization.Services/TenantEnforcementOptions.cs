namespace PixSmith.Authorization.Services;

/// <summary>
/// Settings for tenancy enforcement at the authorization and token endpoints
/// (stage 5 of docs/MULTI-TENANCY.md).
/// </summary>
public sealed class TenantEnforcementOptions
{
    public const string SectionName = "TenantEnforcement";

    /// <summary>
    /// Clients that operate on the auth server itself rather than on a company's data —
    /// the admin UI above all. These are exempt from the membership and subscription checks.
    ///
    /// <para>
    /// The exemption exists because "administer the authorization server" is not a
    /// tenant-scoped activity. Without it, platform staff would need a membership of some
    /// company merely to reach the admin UI, which would make company membership mean two
    /// different things and hand every administrator standing access inside a customer's
    /// tenancy.
    /// </para>
    ///
    /// <para>
    /// This list lives in configuration rather than the database on purpose: an exemption
    /// from an access-control check should not be editable by anything holding only a
    /// database connection. Keep it short, and never add a customer-facing client to it.
    /// </para>
    /// </summary>
    public List<string> PlatformClients { get; set; } = [];

    public bool IsPlatformClient(string? clientId) =>
        !string.IsNullOrWhiteSpace(clientId)
        && PlatformClients.Any(c => string.Equals(c, clientId, StringComparison.OrdinalIgnoreCase));
}
