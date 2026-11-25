namespace PixSmith.Authorization.API.Security;

/// <summary>
/// Browser-hardening headers sent on every response: the login and consent pages, the
/// protocol endpoints, the API and the Blazor admin UI's static files alike.
/// </summary>
public static class SecurityHeaders
{
    /// <summary>
    /// The server-rendered authentication pages. They are the credential-entry surface and
    /// load no JavaScript, so they get a far stricter policy than the rest of the server.
    /// </summary>
    private static readonly string[] AuthPathPrefixes =
    [
        "/Account",          // login, access denied
        "/connect/verify",   // device-flow approval — also credential-adjacent, also no JS
    ];

    /// <summary>
    /// Nothing loads unless named. The login page needs its own stylesheet, a favicon, and
    /// the ability to post its form — and nothing else. In particular <c>script-src</c> is
    /// absent, which <c>default-src 'none'</c> makes a deny: no inline handler, no injected
    /// tag and no third-party include can execute on the page where passwords are typed.
    /// </summary>
    private const string AuthPolicy =
        "default-src 'none'; " +
        "style-src 'self'; " +
        "img-src 'self' data:; " +
        "form-action 'self'; " +
        "frame-ancestors 'none'; " +
        "base-uri 'self'";

    /// <summary>
    /// The Blazor admin UI and the API. Deliberately does not restrict <c>script-src</c>:
    /// index.html still loads Tailwind from a CDN, and constraining scripts before that is
    /// vendored would break the UI. Tightening this is the remaining half of that work.
    /// </summary>
    private const string DefaultPolicy =
        "frame-ancestors 'none'; " +
        "object-src 'none'; " +
        "base-uri 'self'";

    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app) =>
        app.Use(async (context, next) =>
        {
            var headers = context.Response.Headers;

            // Stops a browser reinterpreting a response as a different content type, e.g.
            // running uploaded or reflected text as script.
            headers.XContentTypeOptions = "nosniff";

            headers.ContentSecurityPolicy =
                AuthPathPrefixes.Any(prefix => context.Request.Path.StartsWithSegments(
                    prefix, StringComparison.OrdinalIgnoreCase))
                    ? AuthPolicy
                    : DefaultPolicy;

            // Nothing in this server is meant to be embedded: a hostile site could overlay
            // the login page in a hidden frame and steer a signed-in user's clicks.
            // frame-ancestors above is the modern control; this covers older browsers.
            headers.XFrameOptions = "DENY";

            // Authorization URLs carry state, codes and return URLs in the query string; none
            // of that should leak to another site through the Referer header.
            headers["Referrer-Policy"] = "no-referrer";

            await next();
        });
}
