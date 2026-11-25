using System.Net;
using FluentAssertions;
using Xunit;

namespace PixSmith.Authorization.IntegrationTests.Controllers;

/// <summary>
/// The login page is the credential-entry surface. It used to load Tailwind from a CDN —
/// third-party JavaScript, no subresource integrity, on the page where passwords are typed.
/// These tests pin the properties that replaced it.
/// </summary>
public sealed class LoginPageHardeningTests(AuthWebApplicationFactory factory)
    : IClassFixture<AuthWebApplicationFactory>
{
    private readonly HttpClient client = factory.CreateClient();

    [Fact]
    public async Task Login_page_loads_no_script_at_all()
    {
        var response = await client.GetAsync("/Account/Login");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var html = await response.Content.ReadAsStringAsync();
        html.Should().NotContain("<script",
            "the credential page must execute no JavaScript, which is what makes a deny-all "
            + "script-src possible");
    }

    [Fact]
    public async Task Login_page_references_no_third_party_origin()
    {
        var html = await (await client.GetAsync("/Account/Login")).Content.ReadAsStringAsync();

        html.Should().NotContain("cdn.tailwindcss.com");
        html.Should().NotContain("//", "no protocol-relative or absolute external references");
    }

    [Fact]
    public async Task Login_page_forbids_script_via_csp()
    {
        var response = await client.GetAsync("/Account/Login");

        var csp = response.Headers.GetValues("Content-Security-Policy").Single();

        // default-src 'none' with no script-src override is what denies script.
        csp.Should().Contain("default-src 'none'");
        csp.Should().NotContain("script-src");
        csp.Should().Contain("frame-ancestors 'none'");
    }

    [Fact]
    public async Task Login_stylesheet_is_served_from_this_origin()
    {
        var response = await client.GetAsync("/css/auth.css");

        response.StatusCode.Should().Be(HttpStatusCode.OK,
            "the page's styles must come from the server, not a CDN");
        response.Content.Headers.ContentType!.MediaType.Should().Be("text/css");
    }

    [Fact]
    public async Task Non_auth_responses_keep_the_looser_policy()
    {
        // The SPA still needs its CDN script until Tailwind is vendored, so the strict
        // policy must not leak onto those paths and break the admin UI.
        var response = await client.GetAsync("/.well-known/openid-configuration");

        var csp = response.Headers.GetValues("Content-Security-Policy").Single();
        csp.Should().NotContain("default-src 'none'");
        csp.Should().Contain("frame-ancestors 'none'");
    }
}
