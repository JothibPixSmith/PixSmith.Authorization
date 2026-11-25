using FluentAssertions;
using Xunit;

namespace PixSmith.Authorization.IntegrationTests.Controllers;

/// <summary>
/// Pins the attributes on the cookies this server issues. A pen test found the antiforgery
/// cookie missing <c>Secure</c> — it had no <c>AddAntiforgery</c> call at all, so it ran on
/// framework defaults, which do not set it.
///
/// <para>
/// Only the attributes that hold over the test host's plain HTTP are asserted here. Secure
/// and the <c>__Host-</c> prefix are deliberately conditional on the environment — see
/// CookieHardening and its unit tests — and are verified against the staging stack, which
/// actually serves HTTPS.
/// </para>
/// </summary>
public sealed class CookieHardeningTests(AuthWebApplicationFactory factory)
    : IClassFixture<AuthWebApplicationFactory>
{
    private readonly HttpClient client = factory.CreateClient();

    private async Task<string> AntiforgeryCookieAsync()
    {
        var response = await client.GetAsync("/Account/Login");
        var cookies = response.Headers.TryGetValues("Set-Cookie", out var values)
            ? values.ToList()
            : [];

        return cookies.SingleOrDefault(c => c.Contains("Antiforgery", StringComparison.OrdinalIgnoreCase))
            ?? throw new Xunit.Sdk.XunitException(
                "no antiforgery cookie was issued by /Account/Login; "
                + $"cookies seen: {string.Join(" | ", cookies)}");
    }



    [Fact]
    public async Task Antiforgery_cookie_is_http_only_and_same_site_strict()
    {
        var cookie = await AntiforgeryCookieAsync();

        cookie.Should().Contain("httponly");
        cookie.Should().Contain("samesite=strict");
    }

}
