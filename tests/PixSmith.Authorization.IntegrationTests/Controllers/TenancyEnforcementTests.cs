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
        // OpenIddictSeeder on startup, which is what makes it usable here as the
        // platform-client case.
        await _factory.RegisterClientAsync("tenant-app", ["authorization_code"], ["openid", "api"]);
    }

    public Task DisposeAsync()
    {
        _client.Dispose();
        _factory.Dispose();
        return Task.CompletedTask;
    }

    /// <summary>
    /// Drives authorization code + PKCE, the way a browser does. The tenancy decision is made
    /// at the authorization endpoint, so a refusal arrives as <c>error=access_denied</c> on the
    /// redirect rather than as a failed token request.
    /// </summary>
    private Task<SecurityWebApplicationFactory.TokenOutcome> TokenAsync(
        string clientId, string userName, string scope = "openid api",
        string? organization = null) =>
        _factory.TryGetUserTokenAsync(clientId, $"{userName}@test.local", scope, organization);

    /// <summary>
    /// Reads a claim that may be a single value or a list. A JWT collapses a single-valued
    /// claim to a scalar rather than a one-element array, so <c>roles</c> arrives as a string
    /// when the user holds one role and as an array when they hold several. Anything consuming
    /// the claim has to cope with both.
    /// </summary>
    // string[] rather than string?[]: a claim that is present always carries a string value,
    // and a nullable element type makes Assert.Equal's IEquatable<T> constraint unsatisfiable.
    private static string[] ClaimValues(JsonElement claims, string name) =>
        !claims.TryGetProperty(name, out var value) ? []
        : value.ValueKind == JsonValueKind.Array
            ? [.. value.EnumerateArray().Select(v => v.GetString() ?? string.Empty)]
            : [value.GetString() ?? string.Empty];

    private static JsonElement Claims(string accessToken)
    {
        var payload = accessToken.Split('.')[1];
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

        var outcome = await TokenAsync("tenant-app", "alice");

        Assert.True(outcome.Succeeded, outcome.ErrorDescription);

        var claims = Claims(outcome.AccessToken!);
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

        var outcome = await TokenAsync("tenant-app", "bob");

        Assert.False(outcome.Succeeded);
        Assert.Equal("access_denied", outcome.Error);
        Assert.Contains("not subscribed", outcome.ErrorDescription);
    }

    [Fact]
    public async Task A_user_with_no_membership_is_refused_a_tenant_application()
    {
        await _factory.CreateUserAsync("carol");

        var outcome = await TokenAsync("tenant-app", "carol");

        Assert.False(outcome.Succeeded);
        Assert.Equal("access_denied", outcome.Error);
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

        var deniedOutcome = await TokenAsync("tenant-app", "dan");
        var colleagueOutcome = await TokenAsync("tenant-app", "erin");

        Assert.False(deniedOutcome.Succeeded);
        Assert.Equal("access_denied", deniedOutcome.Error);
        // The administrative reason must not reach the denied user.
        Assert.DoesNotContain("denied by test", deniedOutcome.ErrorDescription);

        // The whole point of a per-member denial: colleagues keep working.
        Assert.True(colleagueOutcome.Succeeded, colleagueOutcome.ErrorDescription);
    }

    [Fact]
    public async Task An_inactive_company_refuses_its_members()
    {
        var tenantId = await _factory.CreateTenantAsync("Acme Corp");
        var userId = await _factory.CreateUserAsync("frank");
        await _factory.AddMemberAsync(tenantId, userId, ["Member"]);
        await _factory.SubscribeAsync(tenantId, "tenant-app");

        await _factory.DeactivateTenantAsync(tenantId);

        var outcome = await TokenAsync("tenant-app", "frank");
        Assert.False(outcome.Succeeded);
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

        var outcome = await TokenAsync("blazor-client", "amy");

        Assert.False(outcome.Succeeded);
        Assert.Equal("access_denied", outcome.Error);
    }

    [Fact]
    public async Task A_platform_client_is_reachable_without_a_membership()
    {
        // Otherwise platform-only staff could not reach the admin UI at all. The exemption
        // waives tenancy, so she still needs the platform role.
        await _factory.CreateUserAsync("grace", platformRole: "Admin");

        var outcome = await TokenAsync("blazor-client", "grace");

        Assert.True(outcome.Succeeded, outcome.ErrorDescription);
        Assert.False(Claims(outcome.AccessToken!).TryGetProperty("org_id", out _));
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

        var outcome = await TokenAsync("tenant-app", "heidi");
        var description = outcome.ErrorDescription!;

        Assert.False(outcome.Succeeded);
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

        var outcome = await TokenAsync("tenant-app", "ivan", organization: "globex");

        Assert.True(outcome.Succeeded, outcome.ErrorDescription);

        var claims = Claims(outcome.AccessToken!);
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

        var outcome = await TokenAsync("tenant-app", "judy", organization: "globex");

        Assert.False(outcome.Succeeded);
        Assert.DoesNotContain("Globex", outcome.ErrorDescription!);   // must not confirm it exists
    }
}
