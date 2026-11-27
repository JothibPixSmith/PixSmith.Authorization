using Microsoft.Extensions.Options;
using PixSmith.Authorization.Services.Security;
using Xunit;

namespace PixSmith.Authorization.UnitTests.Services;

/// <summary>
/// CR-13: breached passwords must be refused (ASVS 6.2.4), which is what lets the composition
/// rules go (ASVS 6.2.5).
///
/// <para>
/// The list itself is the interesting part, so these tests load the real embedded one rather
/// than a fixture: a test that passes against three hand-written entries would say nothing
/// about whether the shipped list catches what the pen test found.
/// </para>
/// </summary>
public sealed class CommonPasswordValidatorTests
{
    private static CommonPasswordList Embedded() =>
        new(Options.Create(new CommonPasswordOptions()));

    private static CommonPasswordList FromFile(string path) =>
        new(Options.Create(new CommonPasswordOptions { ListPath = path }));

    private static async Task<bool> AcceptsAsync(CommonPasswordList list, string password)
    {
        var result = await new CommonPasswordValidator<object>(list)
            .ValidateAsync(null!, new object(), password);

        return result.Succeeded;
    }

    [Fact]
    public void The_embedded_list_loads_and_is_larger_than_the_three_thousand_asked_for()
    {
        var list = Embedded();

        Assert.True(list.Enabled);
        Assert.True(list.Count > 3_000, $"the list holds only {list.Count} entries");
        Assert.Contains("embedded", list.Source);
    }

    [Fact]
    public async Task The_password_the_pen_test_got_through_is_refused()
    {
        // "Password1!" is on no list as written — it is "password1" wearing the costume the
        // old composition rules asked for. Catching it is the whole point of comparing the
        // password with its outer punctuation stripped.
        Assert.False(await AcceptsAsync(Embedded(), "Password1!"));
    }

    [Theory]
    [InlineData("password")]
    [InlineData("PASSWORD")]        // the comparison is case-insensitive
    [InlineData("Qwerty123!")]
    [InlineData("password123")]
    [InlineData("!!letmein!!")]     // punctuation at both ends
    [InlineData("administrator")]   // 13 characters, and passes every relaxed rule
    [InlineData("1qaz2wsx3edc")]    // 12 characters, so length alone would not catch it
    public async Task Breached_passwords_are_refused(string password)
    {
        Assert.False(await AcceptsAsync(Embedded(), password));
    }

    [Theory]
    [InlineData("correct horse battery staple")]   // no digit, no uppercase, no symbol
    [InlineData("wandering albatross pentest")]
    [InlineData("AdminTest1234!")]                 // the integration suite's admin password
    [InlineData("UserTest1234!")]
    public async Task Passwords_that_are_merely_long_are_accepted(string password)
    {
        // The individual words appear on the list; the passphrase does not, and matching on
        // words would refuse exactly the passwords this change set out to allow.
        Assert.True(await AcceptsAsync(Embedded(), password));
    }

    [Fact]
    public async Task The_failure_carries_a_code_that_names_the_reason()
    {
        var result = await new CommonPasswordValidator<object>(Embedded())
            .ValidateAsync(null!, new object(), "password");

        Assert.False(result.Succeeded);
        Assert.Contains(result.Errors, e => e.Code == CommonPasswordValidator<object>.ErrorCode);
    }

    [Theory]
    [InlineData("password!", "password")]
    [InlineData("!!password!!", "password")]
    [InlineData("pass!word", "pass!word")]   // only the ends are stripped
    [InlineData("!!!", "")]                  // nothing left, and no exception
    [InlineData("", "")]
    public void Stripping_touches_only_the_ends(string input, string expected)
    {
        Assert.Equal(expected, CommonPasswordList.StripOuterPunctuation(input));
    }

    [Fact]
    public async Task A_password_of_pure_punctuation_does_not_match_an_empty_entry()
    {
        // Stripping "!!!" leaves nothing; comparing that against the list would match any
        // blank line that slipped into it.
        Assert.True(await AcceptsAsync(Embedded(), "!!!!!!!!!!!!!!"));
    }

    [Fact]
    public async Task Disabling_the_check_accepts_everything()
    {
        var list = new CommonPasswordList(
            Options.Create(new CommonPasswordOptions { Enabled = false }));

        Assert.False(list.Enabled);
        Assert.Equal(0, list.Count);
        Assert.True(await AcceptsAsync(list, "password"));
    }

    [Fact]
    public void A_configured_list_that_is_not_there_fails_loudly()
    {
        var missing = Path.Combine(Path.GetTempPath(), $"no-such-list-{Guid.NewGuid():N}.txt");

        var ex = Assert.Throws<InvalidOperationException>(() => FromFile(missing));
        Assert.Contains(missing, ex.Message);
    }

    [Fact]
    public void A_configured_list_with_no_entries_fails_loudly_rather_than_accepting_everything()
    {
        // The failure mode this guards against: a list that loads, holds nothing, and reports
        // every password as fine while looking configured.
        var path = Path.Combine(Path.GetTempPath(), $"empty-list-{Guid.NewGuid():N}.txt");
        File.WriteAllText(path, "# comments only\n\n   \n");

        try
        {
            Assert.Throws<InvalidOperationException>(() => FromFile(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task A_configured_list_replaces_the_embedded_one()
    {
        var path = Path.Combine(Path.GetTempPath(), $"custom-list-{Guid.NewGuid():N}.txt");
        File.WriteAllText(path, "# a deployment's own list\nhunter2\nSwordfish\n");

        try
        {
            var list = FromFile(path);

            Assert.Equal(2, list.Count);
            Assert.Equal(path, list.Source);
            Assert.False(await AcceptsAsync(list, "hunter2"));
            Assert.False(await AcceptsAsync(list, "swordfish"));   // stored lowercased
            Assert.True(await AcceptsAsync(list, "password"));     // embedded list is not consulted
        }
        finally
        {
            File.Delete(path);
        }
    }
}
