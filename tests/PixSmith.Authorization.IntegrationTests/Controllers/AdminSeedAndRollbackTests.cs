using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using PixSmith.Authorization.DataContext;
using Xunit;

namespace PixSmith.Authorization.IntegrationTests.Controllers;

/// <summary>
/// A password the policy refuses has to fail cleanly, in both places one is set without a
/// person present: the admin seed at startup, and registration.
///
/// <para>
/// The hazard is the order of writes. <c>AccountService.RegisterAsync</c> creates the domain
/// half — the <c>UserProfile</c> — before the <c>IdentityUser</c>, so a refusal in between
/// leaves a profile row attached to no account. Nothing reads it (every query starts from
/// Identity) and nothing cleans it up, which is the worst combination: invisible debris that
/// accumulates every time someone picks a password the policy turns down. More likely now that
/// it asks for twelve characters and checks a breach list.
/// </para>
/// </summary>
public sealed class AdminSeedAndRollbackTests
{
    private static async Task<int> ProfileCountAsync(SecurityWebApplicationFactory factory)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        return await db.UserProfiles.CountAsync();
    }

    private static RegisterUserRequest Request(string email, string username, string password) =>
        new(Username: username, Email: email, Password: password, ConfirmPassword: password,
            FirstName: "Test", LastName: "User");

    [Fact]
    public async Task A_registration_the_policy_refuses_leaves_nothing_behind()
    {
        using var factory = new SecurityWebApplicationFactory();
        var client = factory.CreateApiClient();

        var before = await ProfileCountAsync(factory);

        var email = $"{Guid.NewGuid():N}@test.local";
        var username = $"user_{Guid.NewGuid():N}";

        // Eight characters: fine under the old policy, refused under this one.
        var refused = await client.PostAsJsonAsync(
            "/api/account/register", Request(email, username, "Short1!x"));

        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Equal(before, await ProfileCountAsync(factory));

        // And the address is still free, with nothing left over to collide with.
        var accepted = await client.PostAsJsonAsync(
            "/api/account/register", Request(email, username, "wandering albatross pentest"));

        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        Assert.Equal(before + 1, await ProfileCountAsync(factory));
    }

    [Fact]
    public async Task A_registration_refused_for_being_breached_leaves_nothing_behind()
    {
        using var factory = new SecurityWebApplicationFactory();
        var client = factory.CreateApiClient();

        var before = await ProfileCountAsync(factory);

        var response = await client.PostAsJsonAsync("/api/account/register",
            Request($"{Guid.NewGuid():N}@test.local", $"user_{Guid.NewGuid():N}",
                    "administrator"));

        // Thirteen characters, so length lets it through and the breach list is what refuses
        // it — the other half of the policy, and the same cleanup has to hold for it.
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(before, await ProfileCountAsync(factory));
    }

    [Fact]
    public void The_admin_seed_refuses_a_password_the_policy_would_turn_down()
    {
        // Startup fails rather than seeding an administrator nobody can use — and it fails
        // before writing anything, so a corrected password on the next start has a clean slate.
        using var factory = new SecurityWebApplicationFactory(new Dictionary<string, string?>
        {
            ["AdminSeed:Password"] = "short",
        });

        var thrown = Record.Exception(() => factory.CreateApiClient());

        Assert.NotNull(thrown);
        var message = Flatten(thrown);

        Assert.Contains("AdminSeed:Password", message);

        // "Nothing was written" is the assertion that matters, and the only part a failure
        // after the partial write could not claim: the seed used to get as far as creating the
        // profile before Identity turned the password down. A startup that throws either way
        // is not the difference — a startup that throws without leaving debris is.
        Assert.Contains("Nothing was written", message);
    }

    /// <summary>
    /// The hosted service's failure surfaces wrapped, and how deeply depends on the host.
    /// </summary>
    private static string Flatten(Exception? ex)
    {
        var text = new System.Text.StringBuilder();
        while (ex is not null)
        {
            text.AppendLine(ex.Message);
            if (ex is AggregateException aggregate)
                foreach (var inner in aggregate.InnerExceptions) text.AppendLine(Flatten(inner));

            ex = ex.InnerException;
        }

        return text.ToString();
    }
}
