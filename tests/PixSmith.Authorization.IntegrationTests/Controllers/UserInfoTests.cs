using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Xunit;

namespace PixSmith.Authorization.IntegrationTests.Controllers;

/// <summary>
/// OpenID Connect Core §5.3.1: the UserInfo endpoint must support both GET and POST.
/// OpenIddict runs it in passthrough mode, so the controller's routes decide which methods
/// reach it. A missing <c>[HttpPost]</c> shows up as a 405 for POST-only clients.
/// </summary>
public sealed class UserInfoTests : IAsyncLifetime
{
    private SecurityWebApplicationFactory _factory = null!;
    private HttpClient _client = null!;
    private string _accessToken = null!;
    private Guid _userId;

    public async Task InitializeAsync()
    {
        _factory = new SecurityWebApplicationFactory();
        _client = _factory.CreateApiClient();

        await _factory.RegisterClientAsync("tenant-app", ["authorization_code"], ["openid", "api"]);
        var tenantId = await _factory.CreateTenantAsync("Acme Corp");
        _userId = await _factory.CreateUserAsync("alice");
        await _factory.AddMemberAsync(tenantId, _userId, ["Member"]);
        await _factory.SubscribeAsync(tenantId, "tenant-app");

        _accessToken = await _factory.GetUserTokenAsync(
            "tenant-app", "alice@test.local", "openid api");
    }

    public Task DisposeAsync()
    {
        _client.Dispose();
        _factory.Dispose();
        return Task.CompletedTask;
    }

    private async Task AssertUserInfoAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(_userId.ToString(), body.GetProperty("sub").GetString());
    }

    [Fact]
    public async Task Get_with_a_bearer_token_returns_the_user()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);

        await AssertUserInfoAsync(await _client.SendAsync(request));
    }

    [Fact]
    public async Task Post_with_a_bearer_token_returns_the_user()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/connect/userinfo")
        {
            Content = new FormUrlEncodedContent([]),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);

        await AssertUserInfoAsync(await _client.SendAsync(request));
    }

    [Fact]
    public async Task Post_with_the_token_in_the_form_body_returns_the_user()
    {
        // RFC 6750 §2.2, which OIDC Core §5.3.1 allows for POST.
        var response = await _client.PostAsync("/connect/userinfo",
            new FormUrlEncodedContent([new("access_token", _accessToken)]));

        await AssertUserInfoAsync(response);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("POST")]
    public async Task Without_a_token_is_unauthorized(string method)
    {
        using var request = new HttpRequestMessage(new HttpMethod(method), "/connect/userinfo");
        if (method == "POST") request.Content = new FormUrlEncodedContent([]);

        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
