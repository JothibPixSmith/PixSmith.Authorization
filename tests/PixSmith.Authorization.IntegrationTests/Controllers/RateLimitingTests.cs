using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using PixSmith.Authorization.API.Security;
using Xunit;

namespace PixSmith.Authorization.IntegrationTests.Controllers;

/// <summary>
/// Pins the limiter's actual behaviour. The shared factory raises the limit so the rest of
/// the suite can run; these tests lower it through an options override scoped to a host of
/// their own, so they cannot disturb tests running in parallel.
///
/// <para>
/// Each test builds its own host. Every request in this process shares one loopback partition
/// key, so two tests against one host would have the second start with the window already
/// spent.
/// </para>
/// </summary>
public sealed class RateLimitingTests
{
    private const int Limit = 4;

    [Fact]
    public async Task Token_endpoint_rejects_once_the_limit_is_exceeded()
    {
        using var factory = new TightlyLimitedFactory();
        var client = factory.CreateClient();

        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < Limit + 3; i++)
        {
            var response = await client.PostAsync("/connect/token", new FormUrlEncodedContent(
                new Dictionary<string, string>
                {
                    // Any request that reaches the endpoint counts; this one fails
                    // authentication, which is what makes a 429 unambiguously the limiter.
                    ["grant_type"] = "authorization_code",
                    ["code"] = "not-a-real-code",
                    ["client_id"] = "blazor-client",
                }));
            statuses.Add(response.StatusCode);
        }

        // Wrong credentials alone never yield 429, so its presence proves the limiter —
        // not the authentication failure — did the rejecting.
        statuses.Take(Limit).Should().NotContain(HttpStatusCode.TooManyRequests,
            "requests within the limit must be allowed through to normal authentication");
        statuses.Skip(Limit).Should().Contain(HttpStatusCode.TooManyRequests,
            "requests beyond the limit must be rejected by the limiter");
    }

    [Fact]
    public async Task Rejection_carries_Retry_After_so_clients_can_back_off()
    {
        using var factory = new TightlyLimitedFactory();
        var client = factory.CreateClient();

        HttpResponseMessage? rejected = null;
        for (var i = 0; i < Limit + 3 && rejected is null; i++)
        {
            var response = await client.PostAsJsonAsync("/api/account/forgot-password",
                new { Email = "nobody@example.com" });
            if (response.StatusCode == HttpStatusCode.TooManyRequests) rejected = response;
        }

        rejected.Should().NotBeNull("the limiter should reject within the window");
        rejected!.Headers.RetryAfter.Should().NotBeNull();
    }

    [Fact]
    public async Task Exhausting_one_endpoint_does_not_throttle_another()
    {
        // Buckets are per endpoint as well as per address. Sharing one bucket per address
        // would let an attacker flooding the token endpoint deny password resets to everyone
        // behind the same NAT — the limiter becoming a weapon against its own users.
        using var factory = new TightlyLimitedFactory();
        var client = factory.CreateClient();

        for (var i = 0; i < Limit + 3; i++)
        {
            await client.PostAsync("/connect/token", new FormUrlEncodedContent(
                new Dictionary<string, string>
                {
                    // Any request that reaches the endpoint counts; this one fails
                    // authentication, which is what makes a 429 unambiguously the limiter.
                    ["grant_type"] = "authorization_code",
                    ["code"] = "not-a-real-code",
                    ["client_id"] = "blazor-client",
                }));
        }

        var elsewhere = await client.PostAsJsonAsync("/api/account/forgot-password",
            new { Email = "nobody@example.com" });

        elsewhere.StatusCode.Should().NotBe(HttpStatusCode.TooManyRequests);
    }

    [Fact]
    public async Task Limiter_can_be_switched_off_for_deployments_with_one_in_front()
    {
        using var factory = new TightlyLimitedFactory(enabled: false);
        var client = factory.CreateClient();

        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < Limit + 3; i++)
        {
            var response = await client.PostAsJsonAsync("/api/account/forgot-password",
                new { Email = "nobody@example.com" });
            statuses.Add(response.StatusCode);
        }

        statuses.Should().NotContain(HttpStatusCode.TooManyRequests);
    }

    private sealed class TightlyLimitedFactory(bool enabled = true) : AuthWebApplicationFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);

            // Registered after the base factory's headroom, so this wins.
            builder.ConfigureServices(services =>
                services.Configure<RateLimitingOptions>(o =>
                {
                    o.Enabled = enabled;
                    o.Auth.PermitLimit = Limit;
                    o.Auth.WindowSeconds = 60;
                }));
        }
    }
}
