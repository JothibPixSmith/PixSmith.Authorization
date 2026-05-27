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

// ─── Admin API Service ─────────────────────────────────────────────────────

public interface IAdminApiService
{
    Task<DashboardStatsModel> GetDashboardStatsAsync();
    Task<UserPagedResultModel> GetUsersAsync(int page = 1, int pageSize = 20);
    Task UnlockUserAsync(Guid id);
    Task ActivateUserAsync(Guid id);
    Task DeactivateUserAsync(Guid id);
    Task AssignRoleAsync(Guid id, string role);
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
