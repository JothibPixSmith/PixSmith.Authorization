using Microsoft.AspNetCore.Http;

namespace PixSmith.Authorization.API.Security;

/// <summary>
/// Decides how strictly this server's cookies are marked, based on whether the transport is
/// actually HTTPS.
///
/// <para>
/// A pen test found the antiforgery cookie missing <c>Secure</c>. The obvious fix —
/// <c>SecurePolicy.Always</c> everywhere — breaks more than it fixes: unlike cookie
/// authentication, which simply emits the attribute and lets the browser decide, the
/// antiforgery system <b>throws</b> when the policy is <c>Always</c> and the request is not
/// HTTPS. The debug container serves plain HTTP on 8080, so that would turn the login page
/// into a 500 for the entire debug stack.
/// </para>
///
/// <para>
/// So the strict settings apply exactly where the transport can carry them, which is also
/// exactly where OpenIddict enforces HTTPS for protocol requests: everywhere except
/// Development and Testing. Browsers would refuse a <c>Secure</c> or <c>__Host-</c> cookie
/// over plain HTTP anyway, so applying it there would weaken nothing and fix nothing.
/// </para>
/// </summary>
public static class CookieHardening
{
    public sealed record Policy(bool HttpsOnly, CookieSecurePolicy SecurePolicy, string NamePrefix)
    {
        /// <summary>
        /// Prefixes a cookie name only where the prefix is legal. <c>__Host-</c> is enforced by
        /// the browser — it requires Secure, <c>Path=/</c> and no <c>Domain</c> — so applying
        /// it over plain HTTP would make the cookie be dropped rather than tightened.
        /// </summary>
        public string Name(string bareName) => NamePrefix + bareName;
    }

    public static Policy ForEnvironment(IHostEnvironment environment) =>
        environment.IsDevelopment() || environment.IsEnvironment("Testing")
            // SameAsRequest, not None: a dev instance reached over HTTPS still gets Secure.
            ? new Policy(false, CookieSecurePolicy.SameAsRequest, string.Empty)
            : new Policy(true, CookieSecurePolicy.Always, "__Host-");
}
