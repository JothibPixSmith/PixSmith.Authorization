using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Xunit;

namespace PixSmith.Authorization.IntegrationTests.Controllers;

/// <summary>
/// The device authorization grant, and the three change requests from pen testing:
/// clients created through the admin API must actually work (CR-1), the password grant must
/// not be creatable (CR-2), and over-fast polling must be told to slow down (CR-3).
/// </summary>
public sealed class DeviceFlowTests : IAsyncLifetime
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

    private Task<HttpResponseMessage> DeviceAuthorizeAsync(string clientId, string scope = "openid") =>
        _client.PostAsync("/connect/deviceauthorization", new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("client_id", clientId),
            new("scope", scope),
        ]));

    // ── CR-1 ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_device_client_created_through_the_admin_api_is_accepted()
    {
        // The pen test's own verification: a public client with only the device grant,
        // created through the admin API (not straight into the OpenIddict manager, which
        // would bypass the code this covers), must be able to start a device request. Before
        // CR-1 it received the grant permission but not the endpoint permission, so only the
        // seeded provisioning-cli ever worked.
        var created = await _factory.CreateOidcAppAsync(
            "pentest-device", ["urn:ietf:params:oauth:grant-type:device_code"], ["openid"]);
        Assert.True(created.Succeeded, created.Error);

        var response = await DeviceAuthorizeAsync("pentest-device");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(string.IsNullOrEmpty(body.GetProperty("device_code").GetString()));
        Assert.False(string.IsNullOrEmpty(body.GetProperty("user_code").GetString()));
    }

    [Fact]
    public async Task The_short_device_code_alias_works_too()
    {
        // The URN is awkward to type; a caller sending "device_code" should not end up with a
        // permission string the server never matches.
        var created = await _factory.CreateOidcAppAsync(
            "pentest-device-alias", ["device_code"], ["openid"]);
        Assert.True(created.Succeeded, created.Error);

        var response = await DeviceAuthorizeAsync("pentest-device-alias");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task A_client_without_the_device_grant_is_refused_the_endpoint()
    {
        var created = await _factory.CreateOidcAppAsync(
            "code-only", ["authorization_code"], ["openid"]);
        Assert.True(created.Succeeded, created.Error);

        var response = await DeviceAuthorizeAsync("code-only");

        Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
    }

    // ── CR-2 ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task The_password_grant_cannot_be_granted_to_a_new_client()
    {
        // The server refuses the grant, but an admin could still mint a client carrying
        // gt:password — dormant, and quietly live again if the grant were re-enabled.
        var created = await _factory.CreateOidcAppAsync("legacy-ropc", ["password"], ["openid"]);

        Assert.False(created.Succeeded);
        Assert.Contains("not supported", created.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A_client_that_asks_for_the_password_grant_is_not_created_at_all()
    {
        await _factory.CreateOidcAppAsync("legacy-ropc-2", ["password"], ["openid"]);

        Assert.Null(await _factory.FindClientAsync("legacy-ropc-2"));
    }

    // ── CR-3 ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Polling_faster_than_the_interval_is_told_to_slow_down()
    {
        var created = await _factory.CreateOidcAppAsync(
            "pentest-poll", ["urn:ietf:params:oauth:grant-type:device_code"], ["openid"]);
        Assert.True(created.Succeeded, created.Error);

        var device = await (await DeviceAuthorizeAsync("pentest-poll"))
            .Content.ReadFromJsonAsync<JsonElement>();
        var deviceCode = device.GetProperty("device_code").GetString()!;

        var errors = new List<string?>();
        for (var i = 0; i < 4; i++)
        {
            var response = await _client.PostAsync("/connect/token", new FormUrlEncodedContent(
            [
                new KeyValuePair<string, string>(
                    "grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                new("client_id", "pentest-poll"),
                new("device_code", deviceCode),
            ]));

            var body = await response.Content.ReadFromJsonAsync<JsonElement>();
            errors.Add(body.TryGetProperty("error", out var e) ? e.GetString() : null);
        }

        // The first poll is legitimate; the rest arrive inside the interval.
        Assert.Equal("authorization_pending", errors[0]);
        Assert.Contains("slow_down", errors.Skip(1));
    }

    [Fact]
    public async Task A_first_poll_is_never_slowed_down()
    {
        var created = await _factory.CreateOidcAppAsync(
            "pentest-poll-first", ["urn:ietf:params:oauth:grant-type:device_code"], ["openid"]);
        Assert.True(created.Succeeded, created.Error);

        var device = await (await DeviceAuthorizeAsync("pentest-poll-first"))
            .Content.ReadFromJsonAsync<JsonElement>();

        var response = await _client.PostAsync("/connect/token", new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>(
                "grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            new("client_id", "pentest-poll-first"),
            new("device_code", device.GetProperty("device_code").GetString()!),
        ]));

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("authorization_pending", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Polling_one_device_code_does_not_slow_another()
    {
        // State is per device code, not per client or per address: two operators running the
        // flow at once must not throttle each other.
        var created = await _factory.CreateOidcAppAsync(
            "pentest-poll-two", ["urn:ietf:params:oauth:grant-type:device_code"], ["openid"]);
        Assert.True(created.Succeeded, created.Error);

        var first = await (await DeviceAuthorizeAsync("pentest-poll-two"))
            .Content.ReadFromJsonAsync<JsonElement>();
        var second = await (await DeviceAuthorizeAsync("pentest-poll-two"))
            .Content.ReadFromJsonAsync<JsonElement>();

        async Task<string?> PollAsync(JsonElement device)
        {
            var response = await _client.PostAsync("/connect/token", new FormUrlEncodedContent(
            [
                new KeyValuePair<string, string>(
                    "grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                new("client_id", "pentest-poll-two"),
                new("device_code", device.GetProperty("device_code").GetString()!),
            ]));
            var body = await response.Content.ReadFromJsonAsync<JsonElement>();
            return body.TryGetProperty("error", out var e) ? e.GetString() : null;
        }

        Assert.Equal("authorization_pending", await PollAsync(first));
        Assert.Equal("authorization_pending", await PollAsync(second));
    }
}
