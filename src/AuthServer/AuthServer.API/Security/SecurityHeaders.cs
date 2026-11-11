namespace PixSmith.Authorization.API.Security;

/// <summary>
/// Browser-hardening headers sent on every response: the login and consent pages, the
/// protocol endpoints, the API and the Blazor admin UI's static files alike.
/// </summary>
public static class SecurityHeaders
{
    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app) =>
        app.Use(async (context, next) =>
        {
            var headers = context.Response.Headers;

            // Stops a browser reinterpreting a response as a different content type, e.g.
            // running uploaded or reflected text as script.
            headers.XContentTypeOptions = "nosniff";

            // The login page must not be framable: a hostile site could overlay it in a
            // hidden frame and steer a signed-in user's clicks (clickjacking). Nothing in this
            // server is meant to be embedded. frame-ancestors is the modern control;
            // X-Frame-Options covers browsers that predate it. Only frame-ancestors is set, so
            // this does not restrict what the Blazor UI itself may load or run.
            headers.ContentSecurityPolicy = "frame-ancestors 'none'";
            headers.XFrameOptions = "DENY";

            // Authorization URLs carry state, codes and return URLs in the query string; none
            // of that should leak to another site through the Referer header.
            headers["Referrer-Policy"] = "no-referrer";

            await next();
        });
}
