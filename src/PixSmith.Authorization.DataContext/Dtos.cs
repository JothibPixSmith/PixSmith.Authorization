namespace PixSmith.Authorization.DataContext;

// ─── Auth ──────────────────────────────────────────────────────────────────

public sealed record RegisterUserRequest(
	string Username,
	string Email,
	string Password,
	string ConfirmPassword,
	string? FirstName,
	string? LastName);

public sealed record LoginRequest(
	string Email,
	string Password,
	bool RememberMe = false);

public sealed record ForgotPasswordRequest(string Email);

public sealed record ResetPasswordRequest(
	string Email,
	string Token,
	string NewPassword,
	string ConfirmNewPassword);

public sealed record ChangePasswordRequest(
	string CurrentPassword,
	string NewPassword,
	string ConfirmNewPassword);

// ─── Users ─────────────────────────────────────────────────────────────────

public sealed record UserDto(
	Guid Id,
	string Username,
	string Email,
	string? FirstName,
	string? LastName,
	string FullName,
	bool EmailConfirmed,
	bool TwoFactorEnabled,
	bool IsActive,
	bool IsLocked,
	DateTimeOffset CreatedAt,
	DateTimeOffset? LastLoginAt,
	string? ProfilePictureUrl,
	IReadOnlyList<string> Roles);

public sealed record UpdateUserProfileRequest(
	string? FirstName,
	string? LastName,
	string? PhoneNumber,
	string? ProfilePictureUrl);

public sealed record UserPagedResult(
	IReadOnlyList<UserDto> Items,
	int TotalCount,
	int Page,
	int PageSize)
{
	public int TotalPages => (int)Math.Ceiling((double)TotalCount / PageSize);
}

// ─── OAuth Clients ──────────────────────────────────────────────────────────

public sealed record OAuthClientDto(
	Guid Id,
	string ClientId,
	string DisplayName,
	string? Description,
	string ClientType,
	bool IsActive,
	bool RequirePkce,
	bool AllowOfflineAccess,
	int AccessTokenLifetimeSeconds,
	IReadOnlyList<string> RedirectUris,
	IReadOnlyList<string> AllowedScopes,
	IReadOnlyList<string> AllowedGrantTypes,
	DateTimeOffset CreatedAt);

public sealed record CreateOAuthClientRequest(
	string DisplayName,
	string? Description,
	string ClientType,
	IList<string> RedirectUris,
	IList<string> AllowedScopes,
	IList<string> AllowedGrantTypes,
	bool RequireConsent = false,
	bool AllowOfflineAccess = true);

public sealed record CreateOAuthClientResponse(
	Guid Id,
	string ClientId,
	string ClientSecret,
	string DisplayName);

public sealed record UpdateOAuthClientRequest(
	string DisplayName,
	string? Description,
	bool RequireConsent,
	bool AllowOfflineAccess,
	int AccessTokenLifetimeSeconds,
	int IdentityTokenLifetimeSeconds);

public sealed record AdminUpdateUserRequest(
	string Username,
	string Email,
	string? FirstName,
	string? LastName,
	bool EmailConfirmed);

public sealed record AdminResetPasswordRequest(string NewPassword);

public sealed record ClaimDto(string Type, string Value);
public sealed record AddClaimRequest(string Type, string Value);

// ─── Roles ─────────────────────────────────────────────────────────────────

public sealed record RoleDto(Guid Id, string Name);
public sealed record RoleRequest(string RoleName);
public sealed record CreateRoleRequest(string Name);
public sealed record UriRequest(string Uri);

// ─── Tenants ───────────────────────────────────────────────────────────────

public sealed record TenantDto(
	Guid Id,
	string Name,
	string Slug,
	string? Description,
	bool IsActive,
	DateTimeOffset CreatedAt);

public sealed record CreateTenantRequest(string Name, string? Description);
public sealed record UpdateTenantRequest(string Name, string? Description);

// ─── OpenIddict Applications ────────────────────────────────────────────────

public sealed record OidcAppDto(
    string ClientId,
    string? DisplayName,
    string ClientType,
    IReadOnlyList<string> RedirectUris,
    IReadOnlyList<string> PostLogoutRedirectUris,
    IReadOnlyList<string> Permissions,
    IReadOnlyList<string> Requirements,
    IReadOnlyList<OidcAppSigningKeyDto> SigningKeys);

/// <summary>
/// A public signing key registered for client assertions. Only the identifying metadata is
/// returned — enough to confirm which key a deployment is using without shipping the whole
/// key set around.
/// </summary>
public sealed record OidcAppSigningKeyDto(string? Kid, string Kty, string? Alg, string? Use);

public sealed record CreateOidcAppRequest(
    string ClientId,
    string? ClientSecret,
    string? DisplayName,
    string ClientType,
    List<string> RedirectUris,
    List<string> PostLogoutRedirectUris,
    List<string> Scopes,
    List<string> GrantTypes,
    /// <summary>
    /// Raw JWKS JSON for client-assertion (private_key_jwt) authentication — public keys only.
    /// A confidential client needs either this or a ClientSecret; supplying this instead is
    /// what removes the shared secret from config files and deployment pipelines entirely.
    /// </summary>
    string? JsonWebKeySet = null);

public sealed record UpdateOidcAppRequest(
    string? DisplayName,
    List<string> RedirectUris,
    List<string> PostLogoutRedirectUris,
    List<string> Scopes,
    List<string> GrantTypes,
    /// <summary>
    /// Raw JWKS JSON. Null leaves the registered key set untouched; a value replaces it
    /// wholesale. Unlike the client secret this really can be read back, so "keep what is
    /// there" is honestly implementable here.
    /// </summary>
    string? JsonWebKeySet = null);

// ─── Admin Dashboard ───────────────────────────────────────────────────────

public sealed record DashboardStatsDto(
	int TotalUsers,
	int ActiveUsers,
	int LockedUsers,
	int TotalClients,
	int ActiveClients,
	IReadOnlyList<RecentLoginDto> RecentLogins);

public sealed record RecentLoginDto(
	string Username,
	string Email,
	DateTimeOffset LoginAt);

// ─── Tenant Access: memberships and application subscriptions ───────────────
// See docs/MULTI-TENANCY.md. Access to an application is derived — a member may use
// an app when their company subscribes to it — so these two shapes together describe
// everything a user is permitted to reach.

public sealed record TenantMemberDto(
    Guid MembershipId,
    Guid UserId,
    string Username,
    string Email,
    bool IsActive,
    IReadOnlyList<string> Roles,
    IReadOnlyDictionary<string, IReadOnlyList<string>> ApplicationRoles,
    DateTimeOffset CreatedAt);

/// <summary>One company a user belongs to — the data behind a company picker.</summary>
public sealed record UserMembershipDto(
    Guid MembershipId,
    Guid TenantId,
    string TenantName,
    string TenantSlug,
    bool TenantIsActive,
    bool IsActive,
    IReadOnlyList<string> Roles);

public sealed record AddTenantMemberRequest(
    Guid UserId,
    List<string> Roles);

public sealed record UpdateTenantMemberRequest(
    bool IsActive,
    List<string> Roles,
    Dictionary<string, List<string>> ApplicationRoles);

public sealed record TenantApplicationDto(
    Guid Id,
    Guid TenantId,
    string ClientId,
    string? DisplayName,
    bool IsActive,
    DateTimeOffset CreatedAt);

public sealed record AddTenantApplicationRequest(string ClientId);

public sealed record UpdateTenantApplicationRequest(bool IsActive);

// ─── OIDC client secret rotation ────────────────────────────────────────────
// Rotation is a separate operation from updating an application on purpose. Editing a
// redirect URI must never be one forgotten field away from invalidating the credentials
// every deployed copy of that client is using.
//
// OpenIddict stores a single ClientSecret per application — there is no list and no overlap
// window — so rotation is always a hard cutover for everything sharing that client id. The
// mitigation is registration shape, not code: one client per deployment, and client
// assertions (JsonWebKeySet) instead of a shared secret where compromise would matter.
// See INTEGRATION.md, "Register one client per deployment".

/// <summary>Omit the secret to have a cryptographically random one generated.</summary>
public sealed record RotateClientSecretRequest(string? ClientSecret);

/// <summary>
/// Returned once, and only once. OpenIddict stores the secret hashed and will not hand it
/// back, so a caller that loses this value has to rotate again.
/// </summary>
public sealed record RotateClientSecretResponse(string ClientId, string ClientSecret);
