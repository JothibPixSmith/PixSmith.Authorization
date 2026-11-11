using System.Net;
using Microsoft.AspNetCore.HttpOverrides;

namespace PixSmith.Authorization.API.Security;

/// <summary>
/// Decides whose <c>X-Forwarded-For</c> / <c>X-Forwarded-Proto</c> headers the server believes.
///
/// <para>
/// This is a security boundary, not plumbing. OpenIddict's transport-security requirement
/// decides "was this request made over HTTPS?" from the scheme <em>after</em> forwarded headers
/// are applied. Trust them from any sender and a client talking plain HTTP straight to the
/// container can add <c>X-Forwarded-Proto: https</c> and send passwords and tokens in
/// cleartext. It also lets them forge the client IP recorded in logs and the audit trail.
/// </para>
///
/// <para>
/// So the headers are honoured only from the reverse proxies named in configuration:
/// </para>
/// <code>
/// ForwardedHeaders:KnownProxies:0    10.0.0.5          single proxy address
/// ForwardedHeaders:KnownNetworks:0   172.18.0.0/16     e.g. the Docker network the proxy is on
/// ForwardedHeaders:Disabled          true              TLS terminates at Kestrel; no proxy at all
/// </code>
///
/// <para>
/// Outside Development and Testing the server refuses to start with none of these set, the
/// same fail-closed stance as the token certificates: the alternative is either trusting
/// everyone, or trusting no one and having every protocol endpoint reject the proxy's
/// requests with "This server only accepts HTTPS requests".
/// </para>
/// </summary>
public static class ForwardedHeadersSetup
{
    public const string SectionName = "ForwardedHeaders";

    public static void Configure(
        IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
        var section = configuration.GetSection(SectionName);

        if (section.GetValue<bool>("Disabled"))
        {
            services.Configure<ForwardedHeadersOptions>(options =>
                options.ForwardedHeaders = ForwardedHeaders.None);
            return;
        }

        var proxies = ReadList(section, "KnownProxies")
            .Select(value => IPAddress.TryParse(value, out var address)
                ? address
                : throw Invalid("KnownProxies", value, "an IP address such as 10.0.0.5"))
            .ToList();

        var networks = ReadList(section, "KnownNetworks")
            .Select(value => System.Net.IPNetwork.TryParse(value, out var network)
                ? network
                : throw Invalid("KnownNetworks", value, "a CIDR range such as 172.18.0.0/16"))
            .ToList();

        var trustAnySender = false;

        if (proxies.Count == 0 && networks.Count == 0)
        {
            if (environment.IsDevelopment())
            {
                // The debug container is reached through Docker's port mapping, whose source
                // address is not predictable. Nothing here is exposed beyond the developer's
                // machine, and the transport-security requirement is off in Development anyway.
                trustAnySender = true;
            }
            else if (!environment.IsEnvironment("Testing"))
            {
                throw new InvalidOperationException(
                    $"""
                    No trusted reverse proxies are configured and the environment is '{environment.EnvironmentName}'.

                    Forwarded headers decide whether a request counts as HTTPS. Trusting them from
                    any sender lets a client bypass the HTTPS requirement by adding
                    'X-Forwarded-Proto: https' to a plain-HTTP request.

                    Name the proxy that terminates TLS, using either:
                      {SectionName}:KnownProxies:0    <proxy IP address>
                      {SectionName}:KnownNetworks:0   <CIDR range, e.g. the proxy's Docker network>

                    Or, if TLS terminates at this server and there is no proxy:
                      {SectionName}:Disabled          true
                    """);
            }
            // Testing keeps the framework default (loopback only), the same as production
            // with nothing extra trusted, so the test suite exercises the real rejection path.
        }

        services.Configure<ForwardedHeadersOptions>(options =>
        {
            options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;

            if (trustAnySender || proxies.Count > 0 || networks.Count > 0)
            {
                // Replaces the loopback defaults rather than adding to them, so the configured
                // list is exactly what is trusted.
                options.KnownProxies.Clear();
                options.KnownIPNetworks.Clear();
            }

            foreach (var proxy in proxies) options.KnownProxies.Add(proxy);
            foreach (var network in networks) options.KnownIPNetworks.Add(network);
        });
    }

    // Blank entries are ignored so an unset Compose variable (VAR=) reads as "not configured"
    // and hits the startup error above, instead of failing to parse.
    private static IEnumerable<string> ReadList(IConfigurationSection section, string key) =>
        section.GetSection(key).GetChildren()
            .Select(child => child.Value?.Trim())
            .Where(value => !string.IsNullOrEmpty(value))
            .Select(value => value!);

    private static InvalidOperationException Invalid(string key, string value, string expected) =>
        new($"{SectionName}:{key} contains '{value}', which is not {expected}.");
}
