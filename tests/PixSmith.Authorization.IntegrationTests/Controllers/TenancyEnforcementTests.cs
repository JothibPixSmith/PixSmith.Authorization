using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Xunit;

namespace PixSmith.Authorization.IntegrationTests.Controllers;

/// <summary>
/// Tenancy enforcement over real HTTP.
///
/// <para>
/// The unit suite proves the access policy correct in isolation, which says nothing about
/// whether the token endpoint consults it. These tests cover that seam: drop the
/// <c>decision.IsAllowed</c> check from the controller and every unit test still passes
/// while the server silently stops enforcing tenancy.
/// </para>
/// </summary>
public sealed class TenancyEnforcementTests : IAsyncLifetime
{
    private SecurityWebApplicationFactory _factory = null!;
    private HttpClient _client = null!;

    public async Task InitializeAsync()
    {
        _factory = new SecurityWebApplicationFactory();
        _client = _factory.CreateApiClient();

        // Only the tenant-scoped client needs registering: "blazor-client" is seeded by
        // OpenIddictSeeder on startup and already permits the password grant, which is what
        // makes it usable here as the platform-client case.
        await _factory.RegisterClientAsync("tenant-app", ["password"], ["openid", "api"]);
    }

    public Task DisposeAsync()
    {
        _client.Dispose();
        _factory.Dispose();
        return Task.CompletedTask;
    }

    private async Task<(HttpStatusCode Status, JsonElement Body)> TokenAsync(
        string clientId, string userName, string scope = "openid api")
    {
        var response = await _client.PostAsync("/connect/token", new FormUrlEncodedContent(
        [
            new("grant_type", "password"),
            new("username", $"{userName}@test.local"),
            new("password", SecurityWebApplicationFactory.UserPassword),
            new("client_id", clientId),
            new("scope", scope),
        ]));

        return (response.StatusCode, await response.Content.ReadFromJsonAsync<JsonElement>());
    }

    /// <summary>
    /// Reads a claim that may be a single value or a list. A JWT collapses a single-valued
    /// claim to a scalar rather than a one-element array, so <c>roles</c> arrives as a string
    /// when the user holds one role and as an array when they hold several. Anything consuming
    /// the claim has to cope with both.
    /// </summary>
    private static string?[] ClaimValues(JsonElement claims, string name) =>
        !claims.TryGetProperty(name, out var value) ? []
        : value.ValueKind == JsonValueKind.Array
            ? [.. value.EnumerateArray().Select(v => v.GetString())]
            : [value.GetString()];

    private static JsonElement Claims(JsonElement tokenBody)
    {
        var jwt = tokenBody.GetProperty("access_token").GetString()!;
        var payload = jwt.Split('.')[1];
        payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
        return JsonDocument.Parse(Convert.FromBase64String(
            payload.Replace('-', '+').Replace('_', '/'))).RootElement;
    }

    // ── Allowed ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_member_of_a_subscribed_company_receives_a_token_carrying_the_context()
    {
        var tenantId = await _factory.CreateTenantAsync("Acme Corp");
        var userId = await _factory.CreateUserAsync("alice");
        await _factory.AddMemberAsync(tenantId, userId, ["Member", "OrgAdmin"]);
        await _factory.SubscribeAsync(tenantId, "tenant-app");

        var (status, body) = await TokenAsync("tenant-app", "alice");

        Assert.Equal(HttpStatusCode.OK, status);

        var claims = Claims(body);
        Assert.Equal(tenantId.ToString(), claims.GetProperty("org_id").GetString());
        Assert.Equal("acme-corp", claims.GetProperty("org_slug").GetString());

        Assert.Equal(["Member", "OrgAdmin"], ClaimValues(claims, "roles").Order());
    }

    // ── The nesting rule, over HTTP ───────────────────────────────────────────

    [Fact]
    public async Task A_member_whose_company_is_not_subscribed_is_refused()
    {
        var tenantId = await _factory.CreateTenantAsync("Acme Corp");
        var userId = await _factory.CreateUserAsync("bob");
        await _factory.AddMemberAsync(tenantId, userId, ["Member"]);
        // deliberately no subscription

        var (status, body) = await TokenAsync("tenant-app", "bob");

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("access_denied", body.GetProperty("error").GetString());
        Assert.Contains("not subscribed", body.GetProperty("error_description").GetString());
    }

    [Fact]
    public async Task A_user_with_no_membership_is_refused_a_tenant_application()
    {
        await _factory.CreateUserAsync("carol");

        var (status, body) = await TokenAsync("tenant-app", "carol");

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("access_denied", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task An_individually_denied_member_is_refused_while_the_subscription_stands()
    {
        var tenantId = await _factory.CreateTenantAsync("Acme Corp");
        var denied = await _factory.CreateUserAsync("dan");
        var colleague = await _factory.CreateUserAsync("erin");

        await _factory.AddMemberAsync(tenantId, denied, ["Member"], denyClientId: "tenant-app");
        await _factory.AddMemberAsync(tenantId, colleague, ["Member"]);
        await _factory.SubscribeAsync(tenantId, "tenant-app");

        var (deniedStatus, deniedBody) = await TokenAsync("tenant-app", "dan");
        var (colleagueStatus, _) = await TokenAsync("tenant-app", "erin");

        Assert.Equal(HttpStatusCode.BadRequest, deniedStatus);
        Assert.Equal("access_denied", deniedBody.GetProperty("error").GetString());
        // The administrative reason must not reach the denied user.
        Assert.DoesNotContain("denied by test", deniedBody.GetProperty("error_description").GetString());

        // The whole point of a per-member denial: colleagues keep working.
        Assert.Equal(HttpStatusCode.OK, colleagueStatus);
    }

    [Fact]
    public async Task An_inactive_company_refuses_its_members()
    {
        var tenantId = await _factory.CreateTenantAsync("Acme Corp");
        var userId = await _factory.CreateUserAsync("frank");
        await _factory.AddMemberAsync(tenantId, userId, ["Member"]);
        await _factory.SubscribeAsync(tenantId, "tenant-app");

        await _factory.DeactivateTenantAsync(tenantId);

        var (status, _) = await TokenAsync("tenant-app", "frank");
        Assert.Equal(HttpStatusCode.BadRequest, status);
    }

    // ── The platform exemption ────────────────────────────────────────────────

    [Fact]
    public async Task A_customer_user_cannot_authenticate_to_the_platform_client()
    {
        // Found by exercising a real customer tenancy: the exemption previously waived
        // tenancy without demanding platform authority, so any customer could obtain a
        // token for the vendor's admin console.
        var tenantId = await _factory.CreateTenantAsync("Riverside Studios");
        var userId = await _factory.CreateUserAsync("amy");
        await _factory.AddMemberAsync(tenantId, userId, ["Member", "OrgAdmin"]);

        var (status, body) = await TokenAsync("blazor-client", "amy");

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("access_denied", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task A_platform_client_is_reachable_without_a_membership()
    {
        // Otherwise platform-only staff could not reach the admin UI at all. The exemption
        // waives tenancy, so she still needs the platform role.
        await _factory.CreateUserAsync("grace", platformRole: "Admin");

        var (status, body) = await TokenAsync("blazor-client", "grace");

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.False(Claims(body).TryGetProperty("org_id", out _));
    }

    [Fact]
    public async Task Ambiguity_across_companies_names_the_users_own_organizations()
    {
        // A bare denial here would be a dead end; the caller must be able to recover.
        var acme = await _factory.CreateTenantAsync("Acme Corp");
        var globex = await _factory.CreateTenantAsync("Globex");
        var userId = await _factory.CreateUserAsync("heidi");

        await _factory.AddMemberAsync(acme, userId, ["Member"]);
        await _factory.AddMemberAsync(globex, userId, ["Member"]);
        await _factory.SubscribeAsync(acme, "tenant-app");
        await _factory.SubscribeAsync(globex, "tenant-app");

        var (status, body) = await TokenAsync("tenant-app", "heidi");
        var description = body.GetProperty("error_description").GetString()!;

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Contains("acme-corp", description);
        Assert.Contains("globex", description);
    }

    [Fact]
    public async Task An_explicit_organization_resolves_the_ambiguity()
    {
        var acme = await _factory.CreateTenantAsync("Acme Corp");
        var globex = await _factory.CreateTenantAsync("Globex");
        var userId = await _factory.CreateUserAsync("ivan");

        await _factory.AddMemberAsync(acme, userId, ["Member"]);
        await _factory.AddMemberAsync(globex, userId, ["OrgAdmin"]);
        await _factory.SubscribeAsync(globex, "tenant-app");

        var response = await _client.PostAsync("/connect/token", new FormUrlEncodedContent(
        [
            new("grant_type", "password"),
            new("username", "ivan@test.local"),
            new("password", SecurityWebApplicationFactory.UserPassword),
            new("client_id", "tenant-app"),
            new("scope", "openid api"),
            new("organization", "globex"),
        ]));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var claims = Claims(await response.Content.ReadFromJsonAsync<JsonElement>());
        Assert.Equal(globex.ToString(), claims.GetProperty("org_id").GetString());
        // One role, so the claim is a scalar rather than an array — see ClaimValues.
        Assert.Equal(["OrgAdmin"], ClaimValues(claims, "roles"));
    }

    [Fact]
    public async Task Requesting_a_company_you_do_not_belong_to_reveals_nothing_about_it()
    {
        var acme = await _factory.CreateTenantAsync("Acme Corp");
        var globex = await _factory.CreateTenantAsync("Globex");
        var userId = await _factory.CreateUserAsync("judy");

        await _factory.AddMemberAsync(acme, userId, ["Member"]);
        await _factory.SubscribeAsync(globex, "tenant-app");

        var response = await _client.PostAsync("/connect/token", new FormUrlEncodedContent(
        [
            new("grant_type", "password"),
            new("username", "judy@test.local"),
            new("password", SecurityWebApplicationFactory.UserPassword),
            new("client_id", "tenant-app"),
            new("scope", "openid api"),
            new("organization", "globex"),
        ]));

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        var description = body.GetProperty("error_description").GetString()!;

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain("Globex", description);   // must not confirm it exists
    }
}
