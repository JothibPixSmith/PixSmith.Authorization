using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Xunit;

namespace PixSmith.Authorization.IntegrationTests.Controllers;

/// <summary>
/// The admin policy over real HTTP: administering the server requires both the platform
/// <c>Admin</c> role and the <c>admin</c> scope.
///
/// <para>
/// Each of these was a live hole at some point. The role alone let any token an administrator
/// held administer the server — including one issued to an unrelated application. The scope
/// alone let a machine client administer with no human involved, and grant itself company
/// memberships. Both directions need a standing test, because both failed silently.
/// </para>
/// </summary>
public sealed class AdminPolicyTests : IAsyncLifetime
{
    private SecurityWebApplicationFactory _factory = null!;
    private HttpClient _client = null!;

    public async Task InitializeAsync()
    {
        _factory = new SecurityWebApplicationFactory();
        _client = _factory.CreateApiClient();

        // A machine client granted admin scope — the identity that used to succeed.
        await _factory.RegisterClientAsync(
            "machine-admin", ["client_credentials"], ["api", "admin"],
            clientSecret: "machine-secret", confidential: true);
    }

    public Task DisposeAsync()
    {
        _client.Dispose();
        _factory.Dispose();
        return Task.CompletedTask;
    }

    private async Task<string> AdminTokenAsync(string scope)
    {
        var response = await _client.PostAsync("/connect/token", new FormUrlEncodedContent(
        [
            new("grant_type", "password"),
            new("username", SecurityWebApplicationFactory.AdminEmail),
            new("password", SecurityWebApplicationFactory.AdminPassword),
            new("client_id", "blazor-client"),
            new("scope", scope),
        ]));

        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        return body.GetProperty("access_token").GetString()!;
    }

    private async Task<HttpStatusCode> GetAdminAsync(string token, string path = "/api/admin/tenants")
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await _client.SendAsync(request);
        return response.StatusCode;
    }

    [Fact]
    public async Task An_administrator_with_the_admin_scope_is_allowed()
    {
        var token = await AdminTokenAsync("openid profile email roles api admin");
        Assert.Equal(HttpStatusCode.OK, await GetAdminAsync(token));
    }

    [Fact]
    public async Task An_administrator_without_the_admin_scope_is_refused()
    {
        // The confused deputy: a token issued to some other application still carries the
        // user's Admin role, but was never granted admin authority.
        var token = await AdminTokenAsync("openid profile email roles api");
        Assert.Equal(HttpStatusCode.Forbidden, await GetAdminAsync(token));
    }

    [Fact]
    public async Task A_machine_client_holding_the_admin_scope_is_refused()
    {
        var response = await _client.PostAsync("/connect/token", new FormUrlEncodedContent(
        [
            new("grant_type", "client_credentials"),
            new("client_id", "machine-admin"),
            new("client_secret", "machine-secret"),
            new("scope", "api admin"),
        ]));

        response.EnsureSuccessStatusCode();
        var token = (await response.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("access_token").GetString()!;

        // It has the scope but no role claim at all, because there is no user.
        Assert.Equal(HttpStatusCode.Forbidden, await GetAdminAsync(token));
    }

    [Fact]
    public async Task A_machine_client_cannot_grant_itself_a_company_membership()
    {
        // The reason the scope-only hole mattered: it would have let a machine identity
        // award itself the very memberships tenancy enforcement relies on.
        var tenantId = await _factory.CreateTenantAsync("Acme Corp");

        var tokenResponse = await _client.PostAsync("/connect/token", new FormUrlEncodedContent(
        [
            new("grant_type", "client_credentials"),
            new("client_id", "machine-admin"),
            new("client_secret", "machine-secret"),
            new("scope", "api admin"),
        ]));
        var token = (await tokenResponse.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("access_token").GetString()!;

        using var request = new HttpRequestMessage(
            HttpMethod.Post, $"/api/admin/tenants/{tenantId}/members")
        {
            Content = JsonContent.Create(new { userId = Guid.NewGuid(), roles = new[] { "OrgAdmin" } }),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await _client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task An_unauthenticated_caller_is_refused()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/admin/tenants");
        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
