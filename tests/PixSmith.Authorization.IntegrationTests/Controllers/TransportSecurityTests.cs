using System.Net;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using PixSmith.Authorization.API.Security;
using Xunit;

namespace PixSmith.Authorization.IntegrationTests.Controllers;

/// <summary>
/// The HTTPS requirement and the forwarded headers that decide it.
///
/// <para>
/// OpenIddict judges "is this HTTPS?" from the scheme after <c>X-Forwarded-Proto</c> is applied.
/// If that header is believed from any sender, a client talking plain HTTP straight to the
/// container passes the check by claiming https. These tests pin that it is believed only from
/// a configured proxy, and that production cannot start without one.
/// </para>
/// </summary>
public sealed class TransportSecurityTests : IDisposable
{
    private const string TrustedProxy = "10.9.8.7";
    private const string Discovery = "/.well-known/openid-configuration";

    private readonly SecurityWebApplicationFactory _factory = new();

    public void Dispose() => _factory.Dispose();

    // ── Over HTTP ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task Spoofed_forwarded_proto_from_an_untrusted_sender_does_not_pass_as_https()
    {
        using var client = HttpClientFor(_factory, remoteIp: "203.0.113.50");

        var response = await client.SendAsync(SpoofedHttps(Discovery));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest,
            "a plain-HTTP request must still be refused when it merely claims to be https");
    }

    [Fact]
    public async Task Forwarded_proto_from_the_configured_proxy_is_honoured()
    {
        // The positive case matters as much as the negative: without it a "fix" that ignored
        // forwarded headers entirely would pass the tests above and break every deployment
        // behind a TLS-terminating proxy.
        using var client = HttpClientFor(_factory, remoteIp: TrustedProxy);

        var response = await client.SendAsync(SpoofedHttps(Discovery));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        body.GetProperty("issuer").GetString().Should().StartWith("https://");
    }

    // ── Browser-hardening headers ──────────────────────────────────────────────

    [Theory]
    [InlineData(Discovery)]
    [InlineData("/Login")]
    [InlineData("/")]
    public async Task Every_response_carries_the_security_headers(string path)
    {
        using var client = _factory.CreateApiClient();

        var response = await client.GetAsync(path);

        Header(response, "X-Content-Type-Options").Should().Be("nosniff");
        Header(response, "X-Frame-Options").Should().Be("DENY");
        Header(response, "Content-Security-Policy").Should().Contain("frame-ancestors 'none'");
        Header(response, "Referrer-Policy").Should().Be("no-referrer");
    }

    // ── Startup configuration ──────────────────────────────────────────────────

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    public void Outside_development_startup_fails_with_no_trusted_proxy(string environment)
    {
        var act = () => ConfigureForwardedHeaders(environment, []);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*No trusted reverse proxies are configured*");
    }

    [Fact]
    public void Blank_entries_count_as_not_configured()
    {
        // What Compose produces for an unset TRUSTED_PROXY_NETWORK.
        var act = () => ConfigureForwardedHeaders("Production",
            new() { ["ForwardedHeaders:KnownNetworks:0"] = "" });

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*No trusted reverse proxies are configured*");
    }

    [Fact]
    public void Malformed_entries_are_rejected_at_startup()
    {
        var act = () => ConfigureForwardedHeaders("Production",
            new() { ["ForwardedHeaders:KnownNetworks:0"] = "172.18.0.0" });

        act.Should().Throw<InvalidOperationException>().WithMessage("*not a CIDR range*");
    }

    [Fact]
    public void Configured_proxies_replace_the_defaults()
    {
        var options = ConfigureForwardedHeaders("Production", new()
        {
            ["ForwardedHeaders:KnownProxies:0"] = "10.0.0.5",
            ["ForwardedHeaders:KnownNetworks:0"] = "172.18.0.0/16",
        });

        options.KnownProxies.Should().ContainSingle().Which.Should().Be(IPAddress.Parse("10.0.0.5"));
        options.KnownIPNetworks.Should().ContainSingle()
            .Which.Should().Be(System.Net.IPNetwork.Parse("172.18.0.0/16"));
        options.ForwardedHeaders.Should().HaveFlag(ForwardedHeaders.XForwardedProto);
    }

    [Fact]
    public void Disabled_ignores_forwarded_headers_and_needs_no_proxy()
    {
        var options = ConfigureForwardedHeaders("Production",
            new() { ["ForwardedHeaders:Disabled"] = "true" });

        options.ForwardedHeaders.Should().Be(ForwardedHeaders.None);
    }

    [Fact]
    public void Development_trusts_any_sender_for_the_debug_container()
    {
        var options = ConfigureForwardedHeaders("Development", []);

        options.KnownProxies.Should().BeEmpty();
        options.KnownIPNetworks.Should().BeEmpty();
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static HttpRequestMessage SpoofedHttps(string path)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Add("X-Forwarded-Proto", "https");
        return request;
    }

    private static string? Header(HttpResponseMessage response, string name) =>
        response.Headers.TryGetValues(name, out var values) ? values.Single()
        : response.Content.Headers.TryGetValues(name, out values) ? values.Single()
        : null;

    /// <summary>
    /// A plain-HTTP client whose requests arrive from <paramref name="remoteIp"/>, on a host that
    /// trusts <see cref="TrustedProxy"/>. The test server has no real socket, so a startup filter
    /// stamps the address on before the app's own pipeline (forwarded headers included) runs.
    /// That is required, not cosmetic: ASP.NET Core applies forwarded headers when there is no
    /// remote address at all, so an unstamped test request would pass as https whatever is
    /// configured. Kestrel over TCP always has one, which is the case these tests model.
    /// </summary>
    private static HttpClient HttpClientFor(SecurityWebApplicationFactory factory, string remoteIp) =>
        factory.WithWebHostBuilder(builder =>
            {
                builder.UseSetting("ForwardedHeaders:KnownProxies:0", TrustedProxy);
                builder.ConfigureServices(services =>
                    services.AddSingleton<IStartupFilter>(new RemoteAddressFilter(IPAddress.Parse(remoteIp))));
            })
            .CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("http://localhost/") });

    private sealed class RemoteAddressFilter(IPAddress address) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use((context, nextMiddleware) =>
            {
                context.Connection.RemoteIpAddress = address;
                return nextMiddleware();
            });
            next(app);
        };
    }

    private static ForwardedHeadersOptions ConfigureForwardedHeaders(
        string environmentName, Dictionary<string, string?> settings)
    {
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();

        ForwardedHeadersSetup.Configure(services, configuration, new FakeEnvironment(environmentName));

        return services.BuildServiceProvider().GetRequiredService<IOptions<ForwardedHeadersOptions>>().Value;
    }

    private sealed class FakeEnvironment(string name) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = name;
        public string ApplicationName { get; set; } = "PixSmith.Authorization.API";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
