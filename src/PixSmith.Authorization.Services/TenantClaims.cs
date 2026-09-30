namespace PixSmith.Authorization.Services;

/// <summary>
/// Claim names for company context. See docs/MULTI-TENANCY.md.
/// </summary>
public static class TenantClaims
{
    /// <summary>
    /// The active company. No registered claim exists for this — Azure AD uses <c>tid</c> and
    /// Auth0 uses <c>org_id</c>; this follows the latter. It is the one genuine extension in
    /// the design; everything else adopts a registered name.
    /// </summary>
    public const string OrganizationId = "org_id";

    /// <summary>Human-readable companion to <see cref="OrganizationId"/>, for logs and URLs.</summary>
    public const string OrganizationSlug = "org_slug";

    /// <summary>
    /// Effective roles for this (user, company, application) — registered by RFC 9068 for JWT
    /// access tokens.
    ///
    /// <para>
    /// Deliberately <b>plural</b>, and distinct from the existing singular <c>role</c> claim,
    /// which continues to carry platform-level Identity roles unchanged. Overloading <c>role</c>
    /// would have swapped the admin API's authority out from under it the moment a company
    /// context resolved — the <c>AdminAccess</c> policy reads that claim. Resource servers should
    /// read <c>roles</c>; <c>role</c> can be retired once nothing depends on it.
    /// </para>
    /// </summary>
    public const string Roles = "roles";
}
