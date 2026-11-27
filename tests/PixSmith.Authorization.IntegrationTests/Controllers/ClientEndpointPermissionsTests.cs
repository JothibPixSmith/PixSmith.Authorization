using System.Net;
using Xunit;

namespace PixSmith.Authorization.IntegrationTests.Controllers;

/// <summary>
/// CR-7: a client created through the admin API must be able to revoke its own tokens.
///
/// <para>
/// <c>OidcAppService</c> granted the token endpoint, and the authorization and end-session
/// endpoints where they applied, but never revocation. OpenIddict refuses an endpoint a client
/// holds no <c>ept:…</c> permission for, so no such client could revoke anything: a user's
/// refresh token survived their logout, and a refresh token is the credential that buys new
/// access tokens for as long as it lives.
/// </para>
///
/// <para>
/// Introspection is the opposite case and stays opt-in. Revoking is a client disposing of its
/// own credential; introspecting is asking the server about tokens the caller was not given,
/// which is a resource server's business.
/// </para>
/// </summary>
public sealed class ClientEndpointPermissionsTests : IAsyncLifetime
{
    private SecurityWebApplicationFactory _factory = null!;
    private HttpClient _client = null!;

    public Task InitializeAsync()
    {
        _factory = new SecurityWebApplicationFactory();
        _client = _factory.CreateApiClient();
        return Task.CompletedTask;
    }

    public Task DisposeAsync()
    {
        _client.Dispose();
        _factory.Dispose();
        return Task.CompletedTask;
    }

    // ── Registered permissions ───────────────────────────────────────────────

    [Fact]
    public async Task Every_client_is_granted_the_revocation_endpoint()
    {
        var created = await _factory.CreateOidcAppAsync(
            "revoker-public", ["authorization_code", "refresh_token"], ["openid", "offline_access"]);
        Assert.True(created.Succeeded, created.Error);

        var permissions = await _factory.GetClientPermissionsAsync("revoker-public");

        Assert.Contains("ept:revocation", permissions);
    }

    [Fact]
    public async Task A_confidential_client_is_granted_it_too()
    {
        var created = await _factory.CreateOidcAppAsync(
            "revoker-confidential", ["client_credentials"], ["api"], confidential: true);
        Assert.True(created.Succeeded, created.Error);

        var permissions = await _factory.GetClientPermissionsAsync("revoker-confidential");

        Assert.Contains("ept:revocation", permissions);
    }

    [Fact]
    public async Task Introspection_is_not_granted_unless_it_is_asked_for()
    {
        var created = await _factory.CreateOidcAppAsync(
            "quiet-client", ["client_credentials"], ["api"], confidential: true);
        Assert.True(created.Succeeded, created.Error);

        var permissions = await _factory.GetClientPermissionsAsync("quiet-client");

        Assert.DoesNotContain("ept:introspection", permissions);
    }

    [Fact]
    public async Task Introspection_is_granted_to_a_confidential_client_that_asks()
    {
        var created = await _factory.CreateOidcAppAsync(
            "resource-server", ["client_credentials"], ["api"],
            confidential: true, allowIntrospection: true);
        Assert.True(created.Succeeded, created.Error);

        var permissions = await _factory.GetClientPermissionsAsync("resource-server");

        Assert.Contains("ept:introspection", permissions);
    }

    [Fact]
    public async Task Introspection_is_refused_for_a_public_client()
    {
        // Refused rather than quietly dropped, for the same reason the password grant is: a
        // permission that cannot work makes a client look configured while it fails at the
        // endpoint. The introspection endpoint authenticates its caller.
        var created = await _factory.CreateOidcAppAsync(
            "public-introspector", ["authorization_code"], ["openid"],
            confidential: false, allowIntrospection: true);

        Assert.False(created.Succeeded);
        Assert.Contains("confidential", created.Error);
        Assert.Null(await _factory.FindClientAsync("public-introspector"));
    }

    // ── End to end ───────────────────────────────────────────────────────────

    [Fact]
    public async Task A_revoked_refresh_token_cannot_be_redeemed()
    {
        // The permission assertions above say the registration is right; this says the client
        // can actually use it. Both matter — CR-1 was exactly the case where the registration
        // looked complete and the endpoint still refused.
        var created = await _factory.CreateOidcAppAsync(
            "pentest-web", ["authorization_code", "refresh_token"],
            ["openid", "offline_access"]);
        Assert.True(created.Succeeded, created.Error);

        // Not a platform client, so the caller needs a company that subscribes to it.
        var tenantId = await _factory.CreateTenantAsync("Pentest Ltd");
        var userId = await _factory.CreateUserAsync("bob");
        await _factory.AddMemberAsync(tenantId, userId, ["Member"]);
        await _factory.SubscribeAsync(tenantId, "pentest-web");

        var tokens = await _factory.GetUserTokensAsync(
            "pentest-web", "bob@test.local", "openid offline_access");

        Assert.NotNull(tokens.RefreshToken);

        var revoked = await _client.PostAsync("/connect/revoke", new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("token", tokens.RefreshToken!),
            new("client_id", "pentest-web"),
        ]));

        Assert.Equal(HttpStatusCode.OK, revoked.StatusCode);

        var refreshed = await _client.PostAsync("/connect/token", new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("grant_type", "refresh_token"),
            new("client_id", "pentest-web"),
            new("refresh_token", tokens.RefreshToken!),
        ]));

        Assert.Equal(HttpStatusCode.BadRequest, refreshed.StatusCode);
        Assert.Contains("invalid_grant", await refreshed.Content.ReadAsStringAsync());
    }
}
