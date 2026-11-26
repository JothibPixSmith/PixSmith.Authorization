using System.Net;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using PixSmith.Authorization.DataContext;
using Xunit;

namespace PixSmith.Authorization.IntegrationTests.Controllers;

/// <summary>
/// CR-4 and CR-5: logout must end the session on the server, and a logout request without a
/// valid <c>id_token_hint</c> must be confirmed rather than acted on silently.
///
/// <para>
/// Plus the follow-on: "sign out everywhere" must revoke the user's OAuth credentials too. A
/// session is only one of three things a signed-in user holds, and the refresh token was the
/// one that survived the logout indefinitely.
/// </para>
/// </summary>
public sealed class SessionLifecycleTests : IAsyncLifetime
{
    private SecurityWebApplicationFactory _factory = null!;

    public Task InitializeAsync()
    {
        _factory = new SecurityWebApplicationFactory();
        return Task.CompletedTask;
    }

    public Task DisposeAsync()
    {
        _factory.Dispose();
        return Task.CompletedTask;
    }

    private HttpClient Browser() => _factory.CreateClient(
        new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost/"),
            AllowAutoRedirect = false,
            HandleCookies = true,
        });

    private static string Antiforgery(string html) =>
        System.Text.RegularExpressions.Regex.Match(
            html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;

    /// <summary>Signs in and returns the browser plus the raw session cookie it was given.</summary>
    private async Task<(HttpClient Client, string Cookie)> SignInAsync()
    {
        var client = Browser();

        var form = await client.GetAsync("/Account/Login");
        var token = Antiforgery(await form.Content.ReadAsStringAsync());

        var login = await client.PostAsync("/Account/Login", new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("Email", SecurityWebApplicationFactory.AdminEmail),
            new("Password", SecurityWebApplicationFactory.AdminPassword),
            new("__RequestVerificationToken", token),
        ]));

        Assert.Equal(HttpStatusCode.Found, login.StatusCode);

        var cookie = login.Headers.GetValues("Set-Cookie")
            .First(c => c.Contains("Identity", StringComparison.OrdinalIgnoreCase));

        return (client, cookie.Split(';')[0]);
    }

    private async Task<int> SessionCountAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        return await db.AuthenticationTickets.CountAsync();
    }

    // ── CR-4 ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Signing_in_creates_a_server_side_session()
    {
        // The premise of the whole change: if the session lived only in the cookie there
        // would be nothing here to revoke.
        var before = await SessionCountAsync();

        await SignInAsync();

        Assert.Equal(before + 1, await SessionCountAsync());
    }

    [Fact]
    public async Task The_session_row_is_what_authenticates_not_the_cookie_alone()
    {
        // Deleting the row server-side must be enough to break the cookie, with the browser
        // none the wiser. That — not the cookie's size — is what "server-side session" means.
        var (client, _) = await SignInAsync();

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/connect/verify")).StatusCode);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            await db.AuthenticationTickets.ExecuteDeleteAsync();
        }

        var after = await client.GetAsync("/connect/verify");

        Assert.Equal(HttpStatusCode.Found, after.StatusCode);
        Assert.Contains("/Account/Login", after.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Logout_deletes_the_session_on_the_server()
    {
        var (client, _) = await SignInAsync();
        var during = await SessionCountAsync();

        var page = await client.GetAsync("/Account/Login");   // a page that issues antiforgery
        var token = Antiforgery(await page.Content.ReadAsStringAsync());

        var logout = await client.PostAsync("/Account/Logout", new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("__RequestVerificationToken", token),
        ]));

        Assert.Equal(HttpStatusCode.Found, logout.StatusCode);
        Assert.Equal(during - 1, await SessionCountAsync());
    }

    [Fact]
    public async Task A_cookie_captured_before_logout_stops_working()
    {
        // The point of CR-4. Previously logout only deleted the browser's copy, so a cookie
        // captured beforehand kept authenticating until it expired.
        var (client, cookie) = await SignInAsync();

        var page = await client.GetAsync("/Account/Login");
        var token = Antiforgery(await page.Content.ReadAsStringAsync());
        await client.PostAsync("/Account/Logout", new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("__RequestVerificationToken", token),
        ]));

        // Replay the captured cookie on a fresh client that never signed in. /connect/verify
        // is used as the probe because it needs nothing but the cookie — a hand-built
        // authorization request would be rejected for its redirect_uri before authentication
        // was ever considered.
        var replay = Browser();
        var request = new HttpRequestMessage(HttpMethod.Get, "/connect/verify");
        request.Headers.Add("Cookie", cookie);

        var response = await replay.SendAsync(request);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Contains("/Account/Login", response.Headers.Location!.ToString());
    }

    // ── CR-5 ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Logout_without_an_id_token_hint_asks_for_confirmation()
    {
        var (client, _) = await SignInAsync();
        var before = await SessionCountAsync();

        var response = await client.GetAsync("/connect/logout");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var html = await response.Content.ReadAsStringAsync();
        Assert.Contains("Sign out?", html);

        // And crucially it did nothing yet.
        Assert.Equal(before, await SessionCountAsync());
    }

    [Fact]
    public async Task The_confirmation_page_needs_no_javascript()
    {
        var (client, _) = await SignInAsync();

        var html = await (await client.GetAsync("/connect/logout")).Content.ReadAsStringAsync();

        Assert.DoesNotContain("<script", html);
        Assert.Contains("__RequestVerificationToken", html);
    }

    [Fact]
    public async Task Confirming_the_logout_ends_the_session()
    {
        var (client, _) = await SignInAsync();
        var during = await SessionCountAsync();

        var page = await client.GetAsync("/connect/logout");
        var token = Antiforgery(await page.Content.ReadAsStringAsync());

        var confirmed = await client.PostAsync("/connect/logout", new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("__RequestVerificationToken", token),
        ]));

        Assert.True(
            confirmed.StatusCode is HttpStatusCode.Found or HttpStatusCode.OK,
            $"unexpected status {confirmed.StatusCode}");
        Assert.Equal(during - 1, await SessionCountAsync());
    }

    [Fact]
    public async Task A_logout_post_without_an_antiforgery_token_is_refused()
    {
        // Otherwise the confirmation page would be decoration: any site could post the form
        // on the user's behalf.
        var (client, _) = await SignInAsync();
        var before = await SessionCountAsync();

        var response = await client.PostAsync("/connect/logout", new FormUrlEncodedContent([]));

        Assert.NotEqual(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal(before, await SessionCountAsync());
    }

    // ── Token revocation on "sign out everywhere" ────────────────────────────

    private const string OfflineScope = "openid profile email roles api offline_access";

    private async Task<Guid> AdminIdAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var users = scope.ServiceProvider
            .GetRequiredService<UserManager<IdentityUser<Guid>>>();

        var user = await users.FindByEmailAsync(SecurityWebApplicationFactory.AdminEmail);
        return user!.Id;
    }

    /// <summary>How many of this user's token entries are still usable.</summary>
    private async Task<int> ValidTokenCountAsync(Guid userId)
    {
        using var scope = _factory.Services.CreateScope();
        var tokens = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();

        var valid = 0;
        await foreach (var token in tokens.FindBySubjectAsync(userId.ToString()))
        {
            if (await tokens.GetStatusAsync(token) == OpenIddictConstants.Statuses.Valid)
                valid++;
        }

        return valid;
    }

    private Task<HttpResponseMessage> RefreshAsync(string refreshToken)
    {
        var client = _factory.CreateApiClient();

        return client.PostAsync("/connect/token", new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("grant_type", "refresh_token"),
            new("client_id", "blazor-client"),
            new("refresh_token", refreshToken),
        ]));
    }

    /// <summary>Signs in a second browser and posts the sign-out-everywhere form.</summary>
    private async Task SignOutEverywhereAsync()
    {
        var (client, _) = await SignInAsync();

        var page = await client.GetAsync("/Account/Login");
        var token = Antiforgery(await page.Content.ReadAsStringAsync());

        var response = await client.PostAsync("/Account/LogoutEverywhere",
            new FormUrlEncodedContent(
            [
                new KeyValuePair<string, string>("__RequestVerificationToken", token),
            ]));

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
    }

    [Fact]
    public async Task A_refresh_token_is_usable_while_the_user_is_signed_in()
    {
        // The control. Without this the revocation tests below would pass just as well if
        // refresh were broken outright.
        var tokens = await _factory.GetUserTokensAsync(
            "blazor-client", SecurityWebApplicationFactory.AdminEmail, OfflineScope);

        Assert.NotNull(tokens.RefreshToken);

        var refreshed = await RefreshAsync(tokens.RefreshToken!);

        Assert.Equal(HttpStatusCode.OK, refreshed.StatusCode);
    }

    [Fact]
    public async Task Signing_out_everywhere_revokes_the_refresh_token()
    {
        // The window this closes: the cookie session ended, but the refresh token did not, so
        // a holder could mint a brand-new access token afterwards and keep doing so for the
        // refresh token's whole lifetime — fourteen days by default.
        var tokens = await _factory.GetUserTokensAsync(
            "blazor-client", SecurityWebApplicationFactory.AdminEmail, OfflineScope);

        Assert.NotNull(tokens.RefreshToken);

        await SignOutEverywhereAsync();

        var refreshed = await RefreshAsync(tokens.RefreshToken!);

        Assert.Equal(HttpStatusCode.BadRequest, refreshed.StatusCode);

        var body = await refreshed.Content.ReadAsStringAsync();
        Assert.Contains("invalid_grant", body);
    }

    [Fact]
    public async Task Signing_out_everywhere_leaves_no_valid_token_entry()
    {
        // Covers the rest of what a subject can hold — authorization codes, device codes and
        // access-token entries — not just the refresh token the test above redeems.
        await _factory.GetUserTokensAsync(
            "blazor-client", SecurityWebApplicationFactory.AdminEmail, OfflineScope);

        var userId = await AdminIdAsync();
        Assert.True(await ValidTokenCountAsync(userId) > 0, "no tokens were issued to revoke");

        await SignOutEverywhereAsync();

        Assert.Equal(0, await ValidTokenCountAsync(userId));
    }

    [Fact]
    public async Task An_ordinary_logout_leaves_tokens_alone()
    {
        // Deliberate, and worth pinning down. Ending one browser session is not a statement
        // about the applications the user has authorized; revoking their tokens from under
        // them would sign them out of every client as a side effect of closing one session.
        // "Sign out everywhere" is the action that means that, and it is the one that revokes.
        await _factory.GetUserTokensAsync(
            "blazor-client", SecurityWebApplicationFactory.AdminEmail, OfflineScope);

        var userId = await AdminIdAsync();
        var before = await ValidTokenCountAsync(userId);

        var (client, _) = await SignInAsync();
        var page = await client.GetAsync("/Account/Login");
        var token = Antiforgery(await page.Content.ReadAsStringAsync());
        await client.PostAsync("/Account/Logout", new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("__RequestVerificationToken", token),
        ]));

        Assert.Equal(before, await ValidTokenCountAsync(userId));
    }
}
