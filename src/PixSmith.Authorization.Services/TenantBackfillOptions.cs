namespace PixSmith.Authorization.Services;

/// <summary>
/// Settings for the one-time migration onto the multi-tenant model
/// (stage 3 of docs/MULTI-TENANCY.md).
/// </summary>
public sealed class TenantBackfillOptions
{
    public const string SectionName = "TenantBackfill";

    /// <summary>Display name of the tenancy every pre-existing user and client is moved into.</summary>
    public string TenantName { get; set; } = "Default";

    /// <summary>Company role granted to each migrated user.</summary>
    public string MemberRole { get; set; } = "Member";

    /// <summary>
    /// Company role additionally granted to users who already hold the platform
    /// <c>Admin</c> role, so the people who administered the system before the migration can
    /// still administer the tenancy they land in.
    ///
    /// <para>
    /// This is a migration convenience, not a standing rule: platform roles deliberately do
    /// not flow into a company context, so after the backfill an admin's authority inside a
    /// company comes from this explicit membership rather than from being staff.
    /// </para>
    /// </summary>
    public string AdminRole { get; set; } = "OrgAdmin";
}
