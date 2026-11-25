using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using PixSmith.Authorization.API.Security;
using Xunit;

namespace PixSmith.Authorization.IntegrationTests;

/// <summary>
/// A pen test found the antiforgery cookie missing <c>Secure</c>. The fix cannot simply be
/// "always" — the antiforgery system throws when the policy is <c>Always</c> and the request
/// is not HTTPS, which would turn the login page into a 500 on the plain-HTTP debug
/// container. These pin the resulting trade-off.
/// </summary>
public sealed class CookiePolicyTests
{
    private sealed class Env(string name) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = name;
        public string ApplicationName { get; set; } = "test";
        public string ContentRootPath { get; set; } = "/";
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = null!;
    }

    [Theory]
    [InlineData("Staging")]
    [InlineData("Production")]
    public void Real_deployments_get_Secure_and_the_Host_prefix(string environment)
    {
        var policy = CookieHardening.ForEnvironment(new Env(environment));

        Assert.True(policy.HttpsOnly);
        Assert.Equal(CookieSecurePolicy.Always, policy.SecurePolicy);
        Assert.Equal("__Host-Antiforgery", policy.Name("Antiforgery"));
    }

    [Theory]
    [InlineData("Development")]
    [InlineData("Testing")]
    public void Http_capable_environments_do_not_get_Always(string environment)
    {
        // Always would make the antiforgery system throw on every plain-HTTP request, and a
        // browser would drop a __Host- cookie there regardless — so it would break the debug
        // stack while hardening nothing.
        var policy = CookieHardening.ForEnvironment(new Env(environment));

        Assert.False(policy.HttpsOnly);
        Assert.Equal(CookieSecurePolicy.SameAsRequest, policy.SecurePolicy);
        Assert.Equal("Antiforgery", policy.Name("Antiforgery"));
    }

    [Fact]
    public void Development_still_marks_Secure_when_reached_over_https()
    {
        // SameAsRequest rather than None: `dotnet run` listens on https://localhost:7100, and
        // that session should still get the attribute.
        Assert.Equal(CookieSecurePolicy.SameAsRequest,
            CookieHardening.ForEnvironment(new Env("Development")).SecurePolicy);
    }
}
