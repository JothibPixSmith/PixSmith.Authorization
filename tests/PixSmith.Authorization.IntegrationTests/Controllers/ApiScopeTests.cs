using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Xunit;

namespace PixSmith.Authorization.IntegrationTests.Controllers;

/// <summary>
/// CR-6: the <c>/api</c> surface must be reachable only by a token that was granted the
/// <c>api</c> scope.
///
/// <para>
/// Two separate faults made this a hole. The <c>ApiAccess</c> policy existed but was never
/// applied — the controllers named only the authentication scheme, which asks whether the token
/// is valid, not what it is for — so a token minted for any client reached the account API and
/// the company-administration API alike. And the policy itself accepted either
/// <c>offline_access</c> or <c>api</c>, so even once applied a token that had only asked for a
/// refresh token would have passed.
/// </para>
/// </summary>
public sealed class ApiScopeTests : IAsyncLifetime
{
    private SecurityWebApplicationFactory _factory = null!;
    private HttpClient _client = null!;

    public async Task InitializeAsync()
    {
        _factory = new SecurityWebApplicationFactory();
        _client = _factory.CreateApiClient();

        await Task.CompletedTask;
    }

    public Task DisposeAsync()
    {
        _client.Dispose();
        _factory.Dispose();
        return Task.CompletedTask;
    }

    /// <summary>
    /// Deliberately the administrator. blazor-client is a platform client, so it admits only
    /// users holding the platform role — and it makes the stronger point: what decides these
    /// cases is the scope the token was granted, not who the caller is. An administrator's
    /// token without <c>api</c> is refused exactly like anyone else's.
    /// </summary>
    private Task<string> TokenAsync(string scope) =>
        _factory.GetUserTokenAsync(
            "blazor-client", SecurityWebApplicationFactory.AdminEmail, scope);

    private async Task<HttpStatusCode> GetAsync(string path, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await _client.SendAsync(request);
        return response.StatusCode;
    }

    // ── Refused ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_token_without_the_api_scope_cannot_read_the_account_api()
    {
        // The pen test's own reproduction: alice, granted only openid and profile, got 200.
        var token = await TokenAsync("openid profile");

        Assert.Equal(HttpStatusCode.Forbidden, await GetAsync("/api/account/me", token));
    }

    [Fact]
    public async Task A_token_without_the_api_scope_cannot_reach_the_company_api()
    {
        var token = await TokenAsync("openid profile");

        Assert.Equal(
            HttpStatusCode.Forbidden, await GetAsync("/api/organizations/mine", token));
    }

    [Fact]
    public async Task Offline_access_does_not_stand_in_for_the_api_scope()
    {
        // The second fault, and the subtler one: offline_access is a request for a refresh
        // token. It says nothing about what the token may be used for.
        var token = await TokenAsync("openid offline_access");

        Assert.Equal(HttpStatusCode.Forbidden, await GetAsync("/api/account/me", token));
    }

    [Fact]
    public async Task A_request_with_no_token_at_all_is_unauthorized()
    {
        var response = await _client.GetAsync("/api/account/me");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // ── Allowed ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_token_granted_the_api_scope_is_accepted()
    {
        var token = await TokenAsync("openid profile email roles api");

        Assert.Equal(HttpStatusCode.OK, await GetAsync("/api/account/me", token));
        Assert.Equal(HttpStatusCode.OK, await GetAsync("/api/organizations/mine", token));
    }

    [Fact]
    public async Task Registration_is_still_anonymous()
    {
        // The actions reached before anyone has a token must stay open, or tightening the
        // scope check would have locked everyone out of signing up.
        var response = await _client.PostAsJsonAsync("/api/account/register", new
        {
            username = "newcomer",
            email = "newcomer@test.local",
            password = "Newcomer1234!",
            confirmPassword = "Newcomer1234!",
            firstName = "New",
            lastName = "Comer",
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
