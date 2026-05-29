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
    IReadOnlyList<string> Requirements);

public sealed record CreateOidcAppRequest(
    string ClientId,
    string? ClientSecret,
    string? DisplayName,
    string ClientType,
    List<string> RedirectUris,
    List<string> PostLogoutRedirectUris,
    List<string> Scopes,
    List<string> GrantTypes);

public sealed record UpdateOidcAppRequest(
    string? DisplayName,
    List<string> RedirectUris,
    List<string> PostLogoutRedirectUris,
    List<string> Scopes,
    List<string> GrantTypes);

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
