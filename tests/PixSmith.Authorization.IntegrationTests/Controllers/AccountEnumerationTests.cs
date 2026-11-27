using System.Net;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using PixSmith.Authorization.DataContext;
using Xunit;

namespace PixSmith.Authorization.IntegrationTests.Controllers;

/// <summary>
/// CR-10 to CR-13: none of the credential endpoints may tell a caller whether an address has an
/// account — not by message, and not by how long the answer takes — and the password policy
/// must refuse breached passwords instead of demanding a digit.
///
/// <para>
/// The timing fix is asserted by counting password verifications rather than by measuring a
/// clock: the measurement is what found the finding, but an assertion on elapsed milliseconds
/// in CI would fail for reasons that have nothing to do with this code.
/// </para>
/// </summary>
public sealed class AccountEnumerationTests : IAsyncLifetime
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

    /// <summary>Posts the login form properly, antiforgery token and all.</summary>
    private async Task<HttpResponseMessage> AttemptLoginAsync(string email, string password)
    {
        var client = Browser();

        var form = await client.GetAsync("/Account/Login");
        var token = Regex.Match(
            await form.Content.ReadAsStringAsync(),
            "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;

        return await client.PostAsync("/Account/Login", new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("Email", email),
            new("Password", password),
            new("__RequestVerificationToken", token),
        ]));
    }

    private PixSmith.Authorization.API.Security.DummyPasswordVerifier Verifier() =>
        _factory.Services
            .GetRequiredService<PixSmith.Authorization.API.Security.DummyPasswordVerifier>();

    /// <summary>Bodies of the queued mails to this address whose subject matches.</summary>
    private async Task<string[]> MailsAsync(string email, string subjectContains)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        return await db.EmailOutboxMessages
            .Where(m => m.ToEmail == email && m.Subject.Contains(subjectContains))
            .Select(m => m.Body)
            .ToArrayAsync();
    }

    private Task<string[]> LockoutEmailsAsync(string email) => MailsAsync(email, "locked");

    private Task<string[]> ConfirmationRemindersAsync(string email) =>
        MailsAsync(email, "Confirm your email address to sign in");

    // ── CR-10: password reset ─────────────────────────────────────────────────

    [Fact]
    public async Task Reset_with_a_bad_token_answers_identically_whether_or_not_the_account_exists()
    {
        var client = _factory.CreateApiClient();

        // A real account — the seeded administrator — and an address with no account at all.
        // Both get a token that was never valid.
        var real = await client.PostAsJsonAsync("/api/account/reset-password",
            new ResetPasswordRequest(
                SecurityWebApplicationFactory.AdminEmail, "not-a-token",
                "ReplacementPhrase1", "ReplacementPhrase1"));

        var unknown = await client.PostAsJsonAsync("/api/account/reset-password",
            new ResetPasswordRequest(
                $"{Guid.NewGuid():N}@test.local", "not-a-token",
                "ReplacementPhrase1", "ReplacementPhrase1"));

        Assert.Equal(HttpStatusCode.BadRequest, real.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);

        var realBody = await real.Content.ReadAsStringAsync();
        var unknownBody = await unknown.Content.ReadAsStringAsync();

        // Byte-identical. The real account used to answer with Identity's "Invalid token.",
        // which is all it takes to sort a list of addresses into those worth attacking.
        Assert.Equal(unknownBody, realBody);
        Assert.DoesNotContain("Invalid token", realBody, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Reset_reports_a_password_policy_failure_identically_for_both()
    {
        var client = _factory.CreateApiClient();

        // The second oracle, which survives making the token messages match: validate after
        // the lookup and only existing accounts are ever told their new password is too short.
        var real = await client.PostAsJsonAsync("/api/account/reset-password",
            new ResetPasswordRequest(
                SecurityWebApplicationFactory.AdminEmail, "not-a-token", "short", "short"));

        var unknown = await client.PostAsJsonAsync("/api/account/reset-password",
            new ResetPasswordRequest(
                $"{Guid.NewGuid():N}@test.local", "not-a-token", "short", "short"));

        Assert.Equal(HttpStatusCode.BadRequest, real.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);

        var realBody = await real.Content.ReadAsStringAsync();

        Assert.Equal(await unknown.Content.ReadAsStringAsync(), realBody);

        // Still reported, rather than hidden behind the generic message: the policy describes
        // the password the caller just submitted and says nothing about any account.
        Assert.Contains("12", realBody);
    }

    // ── CR-11: login timing ───────────────────────────────────────────────────

    [Fact]
    public async Task An_unknown_address_still_pays_for_a_password_verification()
    {
        var verifier = Verifier();
        var before = verifier.Invocations;

        var response = await AttemptLoginAsync($"{Guid.NewGuid():N}@test.local", "whatever1234");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);   // the form, redisplayed
        Assert.Contains("Invalid email or password.", await response.Content.ReadAsStringAsync());

        // Without this the response skips the hasher entirely: 4 ms against 72 ms for a real
        // account, which separates cleanly over a handful of samples.
        Assert.Equal(before + 1, verifier.Invocations);
    }

    [Fact]
    public async Task A_real_account_with_a_wrong_password_does_not_use_the_dummy_hash()
    {
        var verifier = Verifier();
        var before = verifier.Invocations;

        await AttemptLoginAsync(SecurityWebApplicationFactory.AdminEmail, "WrongPhrase12345");

        // It hashed the real one. Counting here is what makes the test above mean something:
        // both paths must verify a password exactly once.
        Assert.Equal(before, verifier.Invocations);
    }

    // ── CR-12: lockout ────────────────────────────────────────────────────────

    [Fact]
    public async Task A_locked_out_account_is_refused_in_the_same_words_as_an_unknown_address()
    {
        var name = $"locktarget{Guid.NewGuid():N}"[..20];
        await _factory.CreateUserAsync(name);
        var email = $"{name}@test.local";

        // Identity:Lockout:MaxFailedAccessAttempts is 5 in the test configuration, so the
        // fifth failure trips the lock and the sixth is refused for being locked.
        for (var i = 0; i < 6; i++)
            await AttemptLoginAsync(email, "DefinitelyWrong12345");

        var locked = await AttemptLoginAsync(email, "DefinitelyWrong12345");
        var lockedBody = await locked.Content.ReadAsStringAsync();

        Assert.Contains("Invalid email or password.", lockedBody);
        Assert.DoesNotContain("locked", lockedBody, StringComparison.OrdinalIgnoreCase);

        // And the right password is refused the same way while the lock holds — proving the
        // account really is locked, so the assertion above is about wording and not about the
        // lock having quietly stopped working.
        var correct = await AttemptLoginAsync(email, SecurityWebApplicationFactory.UserPassword);
        var correctBody = await correct.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, correct.StatusCode);   // not the 302 of a sign-in
        Assert.Contains("Invalid email or password.", correctBody);
    }

    [Fact]
    public async Task A_locked_out_attempt_still_pays_for_a_password_verification()
    {
        var name = $"locktiming{Guid.NewGuid():N}"[..20];
        await _factory.CreateUserAsync(name);
        var email = $"{name}@test.local";

        for (var i = 0; i < 5; i++)
            await AttemptLoginAsync(email, "DefinitelyWrong12345");

        var verifier = Verifier();
        var before = verifier.Invocations;

        await AttemptLoginAsync(email, "DefinitelyWrong12345");

        // Identity refuses a locked account before it hashes anything, so this path would
        // answer in milliseconds and give back the oracle the shared wording closes.
        Assert.Equal(before + 1, verifier.Invocations);
    }

    [Fact]
    public async Task Locking_an_account_notifies_its_owner_once()
    {
        var name = $"locknotify{Guid.NewGuid():N}"[..20];
        await _factory.CreateUserAsync(name);
        var email = $"{name}@test.local";

        Assert.Empty(await LockoutEmailsAsync(email));

        for (var i = 0; i < 5; i++)
            await AttemptLoginAsync(email, "DefinitelyWrong12345");

        var afterLocking = await LockoutEmailsAsync(email);
        Assert.Single(afterLocking);
        Assert.Contains("/forgot-password", afterLocking[0]);

        // Every retry after the lock also answers LockedOut. Notifying on each of them would
        // turn a password-guessing run into a way to flood the owner's inbox.
        for (var i = 0; i < 4; i++)
            await AttemptLoginAsync(email, "DefinitelyWrong12345");

        Assert.Single(await LockoutEmailsAsync(email));
    }

    // ── Unconfirmed addresses ─────────────────────────────────────────────────

    [Fact]
    public async Task An_unconfirmed_address_is_refused_in_the_same_words_as_an_unknown_one()
    {
        var name = $"unconfirmed{Guid.NewGuid():N}"[..20];
        await _factory.CreateUserAsync(name, emailConfirmed: false);
        var email = $"{name}@test.local";

        var response = await AttemptLoginAsync(email, SecurityWebApplicationFactory.UserPassword);
        var body = await response.Content.ReadAsStringAsync();

        // It used to answer "Please confirm your email address before signing in.", which
        // every account earns by existing — the one message that gave the game away.
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Invalid email or password.", body);
        Assert.DoesNotContain("confirm your email", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task The_right_password_on_an_unconfirmed_account_sends_a_fresh_link()
    {
        var name = $"needslink{Guid.NewGuid():N}"[..20];
        await _factory.CreateUserAsync(name, emailConfirmed: false);
        var email = $"{name}@test.local";

        await AttemptLoginAsync(email, SecurityWebApplicationFactory.UserPassword);

        var reminders = await ConfirmationRemindersAsync(email);
        Assert.Single(reminders);
        Assert.Contains("/confirm-email", reminders[0]);
    }

    [Fact]
    public async Task A_wrong_password_on_an_unconfirmed_account_sends_nothing()
    {
        var name = $"nolinkfor{Guid.NewGuid():N}"[..20];
        await _factory.CreateUserAsync(name, emailConfirmed: false);
        var email = $"{name}@test.local";

        // Otherwise a run through a password list becomes a way to flood the owner's inbox,
        // and the mail itself becomes the oracle the page no longer is.
        for (var i = 0; i < 3; i++)
            await AttemptLoginAsync(email, "DefinitelyWrong12345");

        Assert.Empty(await ConfirmationRemindersAsync(email));
    }

    [Fact]
    public async Task The_link_in_that_mail_confirms_the_address_and_sign_in_then_works()
    {
        var name = $"linkworks{Guid.NewGuid():N}"[..20];
        await _factory.CreateUserAsync(name, emailConfirmed: false);
        var email = $"{name}@test.local";

        await AttemptLoginAsync(email, SecurityWebApplicationFactory.UserPassword);

        // The mail links to the Blazor page, which calls the API with the same query string.
        var reminder = (await ConfirmationRemindersAsync(email)).Single();
        var href = System.Net.WebUtility.HtmlDecode(
            Regex.Match(reminder, @"href=""([^""]+confirm-email[^""]+)""").Groups[1].Value);
        var query = new Uri(href).Query;

        var confirmed = await _factory.CreateApiClient()
            .GetAsync($"/api/account/confirm-email{query}");
        Assert.Equal(HttpStatusCode.OK, confirmed.StatusCode);

        var signedIn = await AttemptLoginAsync(email, SecurityWebApplicationFactory.UserPassword);
        Assert.Equal(HttpStatusCode.Found, signedIn.StatusCode);   // 302: the session is real
    }

    // ── CR-13: password policy ────────────────────────────────────────────────

    [Theory]
    [InlineData("Password1!")]      // what the pen test got through
    [InlineData("administrator")]   // 13 characters, and passes every rule that is left
    [InlineData("1qaz2wsx3edc")]    // 12 characters, keyboard walk
    public async Task Registration_refuses_a_breached_password(string password)
    {
        var response = await _factory.CreateApiClient().PostAsJsonAsync(
            "/api/account/register",
            new RegisterUserRequest(
                Username: $"user_{Guid.NewGuid():N}",
                Email: $"{Guid.NewGuid():N}@test.local",
                Password: password,
                ConfirmPassword: password,
                FirstName: "Test",
                LastName: "User"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("breach", await response.Content.ReadAsStringAsync(),
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Registration_accepts_a_long_passphrase_with_no_digit_or_uppercase()
    {
        // Refused before this change set for having no digit and no uppercase letter, while
        // Password1! sailed through. That is the trade the composition rules were making.
        const string passphrase = "wandering albatross pentest";

        var response = await _factory.CreateApiClient().PostAsJsonAsync(
            "/api/account/register",
            new RegisterUserRequest(
                Username: $"user_{Guid.NewGuid():N}",
                Email: $"{Guid.NewGuid():N}@test.local",
                Password: passphrase,
                ConfirmPassword: passphrase,
                FirstName: "Test",
                LastName: "User"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
