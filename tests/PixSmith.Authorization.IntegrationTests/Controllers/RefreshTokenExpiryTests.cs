using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace PixSmith.Authorization.IntegrationTests.Controllers;

/// <summary>
/// CR-8: a chain of refresh tokens must reach an absolute expiry (ASVS 10.4.8).
///
/// <para>
/// Each refresh used to issue a token whose lifetime began at that moment, so refreshing often
/// enough meant never signing in again — and a stolen refresh token that kept being used stayed
/// valid for as long as the thief kept using it. The sliding window alone only punishes going
/// idle, which is the one thing an attacker with a working token will not do.
/// </para>
///
/// <para>
/// The arithmetic is covered by <c>RefreshTokenPolicyTests</c>. These tests cover what unit
/// tests cannot: that the token endpoint consults the policy, and that the deadline survives a
/// round trip through an encrypted refresh token — if it did not, every refresh would silently
/// restart the clock and the cap would never be reached.
/// </para>
/// </summary>
public sealed class RefreshTokenExpiryTests
{
    private const string Scope = "openid offline_access";

    private static SecurityWebApplicationFactory Factory(int absolute, int sliding) =>
        new(new Dictionary<string, string?>
        {
            ["RefreshTokens:AbsoluteLifetimeSeconds"] = absolute.ToString(),
            ["RefreshTokens:SlidingLifetimeSeconds"] = sliding.ToString(),
        });

    /// <summary>Signs a member of a subscribed company in and returns their first token pair.</summary>
    private static async Task<(Guid UserId, SecurityWebApplicationFactory.TokenPair Tokens)>
        GrantAsync(SecurityWebApplicationFactory factory, string clientId = "refresh-app")
    {
        await factory.RegisterClientAsync(
            clientId, ["authorization_code", "refresh_token"], ["openid", "offline_access"]);

        var tenantId = await factory.CreateTenantAsync("Refresh Ltd");
        var userId = await factory.CreateUserAsync("rita");
        await factory.AddMemberAsync(tenantId, userId, ["Member"]);
        await factory.SubscribeAsync(tenantId, clientId);

        var tokens = await factory.GetUserTokensAsync(clientId, "rita@test.local", Scope);
        Assert.NotNull(tokens.RefreshToken);

        return (userId, tokens);
    }

    private static Task<HttpResponseMessage> RefreshAsync(
        SecurityWebApplicationFactory factory, string refreshToken, string clientId = "refresh-app")
    {
        var client = factory.CreateApiClient();

        return client.PostAsync("/connect/token", new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("grant_type", "refresh_token"),
            new("client_id", clientId),
            new("refresh_token", refreshToken),
        ]));
    }

    private static async Task<string> RefreshTokenOf(HttpResponseMessage response)
    {
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        return body.GetProperty("refresh_token").GetString()!;
    }

    [Fact]
    public async Task The_deadline_survives_a_refresh_and_does_not_move()
    {
        // The mechanism test, and it has to be sensitive to two separate failures.
        //
        // With no idle timeout every refresh token is pinned to the absolute deadline, so an
        // hour's cap must produce an hour's expiry — not OpenIddict's fourteen-day default,
        // which is what an unapplied lifetime looks like.
        //
        // And the deadline has to come back *out of the refresh token*. If the claim were lost
        // in transit each exchange would recompute "an hour from now" and the expiry would
        // creep forward by however long had passed, so the two refreshes are deliberately
        // spaced further apart than the tolerance allows.
        //
        // The two-second tolerance is for truncation, not slack: the deadline claim is whole
        // unix seconds while the first token's expiry was computed to the tick, so the two can
        // legitimately differ by just under a second in either direction.
        using var factory = Factory(absolute: 3600, sliding: 0);
        var (userId, tokens) = await GrantAsync(factory);

        var original = await factory.RefreshTokenExpiryAsync(userId);
        Assert.NotNull(original);

        var granted = original!.Value - DateTimeOffset.UtcNow;
        Assert.True(
            granted < TimeSpan.FromHours(2),
            $"expected the hour-long cap to bound the token, got {granted}");

        var first = await RefreshAsync(factory, tokens.RefreshToken!);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        var afterFirst = await factory.RefreshTokenExpiryAsync(userId);
        Assert.NotNull(afterFirst);
        Assert.True(
            (afterFirst!.Value - original.Value).Duration() < TimeSpan.FromSeconds(2),
            $"the deadline moved on the first refresh: {original} -> {afterFirst}");

        await Task.Delay(TimeSpan.FromSeconds(5));

        var second = await RefreshAsync(factory, await RefreshTokenOf(first));
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);

        var afterSecond = await factory.RefreshTokenExpiryAsync(userId);
        Assert.True(
            (afterSecond!.Value - original.Value).Duration() < TimeSpan.FromSeconds(2),
            $"the deadline moved on the second refresh: {original} -> {afterSecond}");
    }

    [Fact]
    public async Task A_refresh_after_the_absolute_expiry_is_refused()
    {
        // One second of cap, so the deadline is reached while the test watches.
        using var factory = Factory(absolute: 1, sliding: 0);
        var (_, tokens) = await GrantAsync(factory);

        await Task.Delay(TimeSpan.FromMilliseconds(1500));

        var refused = await RefreshAsync(factory, tokens.RefreshToken!);

        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Contains("invalid_grant", await refused.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task The_idle_timeout_still_bounds_a_token_inside_the_cap()
    {
        // Keeping a sliding window is the stronger configuration: without it a token untouched
        // for the whole cap still works on the last day. This asserts the token gets the idle
        // timeout, not the distant absolute deadline.
        using var factory = Factory(absolute: 86_400, sliding: 60);
        var (userId, _) = await GrantAsync(factory);

        var expiry = await factory.RefreshTokenExpiryAsync(userId);

        Assert.NotNull(expiry);
        Assert.True(
            expiry!.Value - DateTimeOffset.UtcNow < TimeSpan.FromMinutes(5),
            $"expected the 60s idle timeout, got {expiry - DateTimeOffset.UtcNow}");
    }

    [Fact]
    public async Task The_deadline_is_never_published_to_the_client()
    {
        // It is the server's own bookkeeping. A claim with no destination stays inside the
        // refresh token; the default in GetDestinations would have put it in the access token.
        using var factory = Factory(absolute: 3600, sliding: 0);
        var (_, tokens) = await GrantAsync(factory);

        var payload = tokens.AccessToken!.Split('.')[1];
        payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
        var claims = JsonDocument.Parse(Convert.FromBase64String(
            payload.Replace('-', '+').Replace('_', '/'))).RootElement;

        Assert.False(claims.TryGetProperty("refresh_expires_at", out _));
    }
}
