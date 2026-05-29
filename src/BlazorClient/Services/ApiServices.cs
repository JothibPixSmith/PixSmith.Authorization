using System.Net.Http.Json;

namespace PixSmith.Authorization.BlazorClient.Services;

// ─── Models ────────────────────────────────────────────────────────────────

public sealed record DashboardStatsModel(
    int TotalUsers, int ActiveUsers, int LockedUsers,
    int TotalClients, int ActiveClients,
    List<RecentLoginModel> RecentLogins);

public sealed record RecentLoginModel(string Username, string Email, DateTimeOffset LoginAt);

public sealed record UserModel(
    Guid Id, string Username, string Email,
    string? FirstName, string? LastName, string FullName,
    bool EmailConfirmed, bool TwoFactorEnabled,
    bool IsActive, bool IsLocked,
    DateTimeOffset CreatedAt, DateTimeOffset? LastLoginAt,
    string? ProfilePictureUrl, List<string> Roles);

public sealed record UserPagedResultModel(
    List<UserModel> Items, int TotalCount, int Page, int PageSize)
{
    public int TotalPages => (int)Math.Ceiling((double)TotalCount / PageSize);
}

public sealed record OAuthClientModel(
    Guid Id, string ClientId, string DisplayName, string? Description,
    string ClientType, bool IsActive, bool RequirePkce, bool AllowOfflineAccess,
    int AccessTokenLifetimeSeconds,
    List<string> RedirectUris, List<string> AllowedScopes,
    List<string> AllowedGrantTypes, DateTimeOffset CreatedAt);

public sealed class CreateClientFormModel
{
    public string DisplayName { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string ClientType { get; set; } = "Confidential";
    public List<string> RedirectUris { get; set; } = [];
    public List<string> AllowedScopes { get; set; } = ["openid", "profile", "email", "api"];
    public List<string> AllowedGrantTypes { get; set; } = ["authorization_code", "refresh_token"];
}

public sealed record CreateClientResponseModel(Guid Id, string ClientId, string ClientSecret, string DisplayName);

public sealed record RoleModel(Guid Id, string Name);

public sealed record ClaimModel(string Type, string Value);

public sealed class AdminUpdateUserFormModel
{
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public bool EmailConfirmed { get; set; }
}

public sealed record TenantModel(
    Guid Id, string Name, string Slug, string? Description,
    bool IsActive, DateTimeOffset CreatedAt);

public sealed class CreateTenantFormModel
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
}

// ─── Admin API Service ─────────────────────────────────────────────────────

public interface IAdminApiService
{
    Task<DashboardStatsModel> GetDashboardStatsAsync();
    Task<UserPagedResultModel> GetUsersAsync(int page = 1, int pageSize = 20);
    Task UnlockUserAsync(Guid id);
    Task ActivateUserAsync(Guid id);
    Task DeactivateUserAsync(Guid id);
    Task AssignRoleAsync(Guid id, string role);
    Task RemoveRoleAsync(Guid id, string role);
    Task DeleteUserAsync(Guid id);
    Task<UserModel> UpdateUserAsync(Guid id, AdminUpdateUserFormModel model);
    Task ResetPasswordAsync(Guid id, string newPassword);
    Task<List<ClaimModel>> GetClaimsAsync(Guid id);
    Task AddClaimAsync(Guid id, string type, string value);
    Task RemoveClaimAsync(Guid id, string type, string value);
    Task<IEnumerable<RoleModel>> GetRolesAsync();
    Task<RoleModel> CreateRoleAsync(string name);
    Task DeleteRoleAsync(string name);
    Task<IEnumerable<OAuthClientModel>> GetClientsAsync();
    Task<CreateClientResponseModel> CreateClientAsync(CreateClientFormModel model);
    Task DeleteClientAsync(Guid id);
    Task ActivateClientAsync(Guid id);
    Task DeactivateClientAsync(Guid id);
}

public sealed class AdminApiService(HttpClient http) : IAdminApiService
{
    public async Task<DashboardStatsModel> GetDashboardStatsAsync() =>
        await http.GetFromJsonAsync<DashboardStatsModel>("api/admin/dashboard")
        ?? throw new InvalidOperationException("Failed to load dashboard stats.");

    public async Task<UserPagedResultModel> GetUsersAsync(int page = 1, int pageSize = 20) =>
        await http.GetFromJsonAsync<UserPagedResultModel>($"api/admin/users?page={page}&pageSize={pageSize}")
        ?? throw new InvalidOperationException("Failed to load users.");

    public Task UnlockUserAsync(Guid id) =>
        http.PostAsync($"api/admin/users/{id}/unlock", null).AsTask();

    public Task ActivateUserAsync(Guid id) =>
        http.PostAsync($"api/admin/users/{id}/activate", null).AsTask();

    public Task DeactivateUserAsync(Guid id) =>
        http.PostAsync($"api/admin/users/{id}/deactivate", null).AsTask();

    public Task AssignRoleAsync(Guid id, string role) =>
        http.PostAsJsonAsync($"api/admin/users/{id}/roles", new { roleName = role }).AsTask();

    public Task RemoveRoleAsync(Guid id, string role) =>
        http.DeleteAsync($"api/admin/users/{id}/roles/{Uri.EscapeDataString(role)}").AsTask();

    public Task DeleteUserAsync(Guid id) =>
        http.DeleteAsync($"api/admin/users/{id}").AsTask();

    public async Task<UserModel> UpdateUserAsync(Guid id, AdminUpdateUserFormModel model)
    {
        var response = await http.PutAsJsonAsync($"api/admin/users/{id}", new
        {
            model.Username,
            model.Email,
            model.FirstName,
            model.LastName,
            model.EmailConfirmed,
        });
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<UserModel>()
            ?? throw new InvalidOperationException("Failed to update user.");
    }

    public Task ResetPasswordAsync(Guid id, string newPassword) =>
        http.PostAsJsonAsync($"api/admin/users/{id}/reset-password", new { newPassword }).AsTask();

    public async Task<List<ClaimModel>> GetClaimsAsync(Guid id) =>
        await http.GetFromJsonAsync<List<ClaimModel>>($"api/admin/users/{id}/claims") ?? [];

    public Task AddClaimAsync(Guid id, string type, string value) =>
        http.PostAsJsonAsync($"api/admin/users/{id}/claims", new { type, value }).AsTask();

    public Task RemoveClaimAsync(Guid id, string type, string value) =>
        http.DeleteAsync(
            $"api/admin/users/{id}/claims?type={Uri.EscapeDataString(type)}&value={Uri.EscapeDataString(value)}")
        .AsTask();

    public async Task<IEnumerable<RoleModel>> GetRolesAsync() =>
        await http.GetFromJsonAsync<List<RoleModel>>("api/admin/roles") ?? [];

    public async Task<RoleModel> CreateRoleAsync(string name)
    {
        var response = await http.PostAsJsonAsync("api/admin/roles", new { name });
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<RoleModel>()
            ?? throw new InvalidOperationException("Failed to create role.");
    }

    public Task DeleteRoleAsync(string name) =>
        http.DeleteAsync($"api/admin/roles/{Uri.EscapeDataString(name)}").AsTask();

    public async Task<IEnumerable<OAuthClientModel>> GetClientsAsync() =>
        await http.GetFromJsonAsync<List<OAuthClientModel>>("api/admin/clients")
        ?? [];

    public async Task<CreateClientResponseModel> CreateClientAsync(CreateClientFormModel model)
    {
        var response = await http.PostAsJsonAsync("api/admin/clients", new
        {
            model.DisplayName,
            model.Description,
            model.ClientType,
            model.RedirectUris,
            AllowedScopes = model.AllowedScopes,
            AllowedGrantTypes = model.AllowedGrantTypes,
        });
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<CreateClientResponseModel>()
            ?? throw new InvalidOperationException("Failed to create client.");
    }

    public Task DeleteClientAsync(Guid id) =>
        http.DeleteAsync($"api/admin/clients/{id}").AsTask();

    public Task ActivateClientAsync(Guid id) =>
        http.PostAsync($"api/admin/clients/{id}/activate", null).AsTask();

    public Task DeactivateClientAsync(Guid id) =>
        http.PostAsync($"api/admin/clients/{id}/deactivate", null).AsTask();
}

// ─── OpenIddict App Models & Service ──────────────────────────────────────

public sealed record OidcAppModel(
    string ClientId,
    string? DisplayName,
    string ClientType,
    List<string> RedirectUris,
    List<string> PostLogoutRedirectUris,
    List<string> Permissions,
    List<string> Requirements)
{
    public List<string> GrantTypes => Permissions
        .Where(p => p.StartsWith("gt:"))
        .Select(p => p[3..])
        .ToList();

    public List<string> Scopes => Permissions
        .Where(p => p.StartsWith("scp:"))
        .Select(p => p[4..])
        .ToList();

    public bool RequiresPkce => Requirements.Any(r => r.Contains("proof_key"));
}

public sealed class CreateOidcAppFormModel
{
    public string ClientId { get; set; } = string.Empty;
    public string? ClientSecret { get; set; }
    public string? DisplayName { get; set; }
    public string ClientType { get; set; } = "public";
    public List<string> RedirectUris { get; set; } = [];
    public List<string> PostLogoutRedirectUris { get; set; } = [];
    public List<string> Scopes { get; set; } = ["openid", "profile", "email"];
    public List<string> GrantTypes { get; set; } = ["authorization_code", "refresh_token"];
}

public sealed class UpdateOidcAppFormModel
{
    public string? DisplayName { get; set; }
    public List<string> RedirectUris { get; set; } = [];
    public List<string> PostLogoutRedirectUris { get; set; } = [];
    public List<string> Scopes { get; set; } = [];
    public List<string> GrantTypes { get; set; } = [];
}

public interface IOidcAppApiService
{
    Task<List<OidcAppModel>> GetAppsAsync();
    Task<OidcAppModel> CreateAppAsync(CreateOidcAppFormModel model);
    Task UpdateAppAsync(string clientId, UpdateOidcAppFormModel model);
    Task DeleteAppAsync(string clientId);
}

public sealed class OidcAppApiService(HttpClient http) : IOidcAppApiService
{
    public async Task<List<OidcAppModel>> GetAppsAsync() =>
        await http.GetFromJsonAsync<List<OidcAppModel>>("api/admin/oidc-apps") ?? [];

    public async Task<OidcAppModel> CreateAppAsync(CreateOidcAppFormModel model)
    {
        var response = await http.PostAsJsonAsync("api/admin/oidc-apps", new
        {
            model.ClientId,
            model.ClientSecret,
            model.DisplayName,
            model.ClientType,
            model.RedirectUris,
            model.PostLogoutRedirectUris,
            model.Scopes,
            model.GrantTypes,
        });
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<OidcAppModel>()
            ?? throw new InvalidOperationException("Failed to create application.");
    }

    public Task UpdateAppAsync(string clientId, UpdateOidcAppFormModel model) =>
        http.PutAsJsonAsync($"api/admin/oidc-apps/{Uri.EscapeDataString(clientId)}", new
        {
            model.DisplayName,
            model.RedirectUris,
            model.PostLogoutRedirectUris,
            model.Scopes,
            model.GrantTypes,
        }).AsTask();

    public Task DeleteAppAsync(string clientId) =>
        http.DeleteAsync($"api/admin/oidc-apps/{Uri.EscapeDataString(clientId)}").AsTask();
}

// ─── Tenant API Service ────────────────────────────────────────────────────

public interface ITenantApiService
{
    Task<IEnumerable<TenantModel>> GetTenantsAsync();
    Task<TenantModel> CreateTenantAsync(CreateTenantFormModel model);
    Task UpdateTenantAsync(Guid id, CreateTenantFormModel model);
    Task ActivateTenantAsync(Guid id);
    Task DeactivateTenantAsync(Guid id);
    Task DeleteTenantAsync(Guid id);
}

public sealed class TenantApiService(HttpClient http) : ITenantApiService
{
    public async Task<IEnumerable<TenantModel>> GetTenantsAsync() =>
        await http.GetFromJsonAsync<List<TenantModel>>("api/admin/tenants") ?? [];

    public async Task<TenantModel> CreateTenantAsync(CreateTenantFormModel model)
    {
        var response = await http.PostAsJsonAsync("api/admin/tenants", new { model.Name, model.Description });
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<TenantModel>()
            ?? throw new InvalidOperationException("Failed to create tenant.");
    }

    public Task UpdateTenantAsync(Guid id, CreateTenantFormModel model) =>
        http.PutAsJsonAsync($"api/admin/tenants/{id}", new { model.Name, model.Description }).AsTask();

    public Task ActivateTenantAsync(Guid id) =>
        http.PostAsync($"api/admin/tenants/{id}/activate", null).AsTask();

    public Task DeactivateTenantAsync(Guid id) =>
        http.PostAsync($"api/admin/tenants/{id}/deactivate", null).AsTask();

    public Task DeleteTenantAsync(Guid id) =>
        http.DeleteAsync($"api/admin/tenants/{id}").AsTask();
}

// ─── Account API Service ───────────────────────────────────────────────────

public interface IAccountApiService
{
    Task<UserModel?> GetCurrentUserAsync();
}

public sealed class AccountApiService(HttpClient http) : IAccountApiService
{
    public async Task<UserModel?> GetCurrentUserAsync() =>
        await http.GetFromJsonAsync<UserModel>("api/account/me");
}

// Extension to convert HttpResponseMessage Task to void Task
file static class Extensions
{
    public static async Task AsTask(this Task<HttpResponseMessage> task)
    {
        var response = await task;
        response.EnsureSuccessStatusCode();
    }
}
