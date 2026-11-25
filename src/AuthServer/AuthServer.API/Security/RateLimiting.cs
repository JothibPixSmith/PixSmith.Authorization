using System.Globalization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;

namespace PixSmith.Authorization.API.Security;

/// <summary>
/// Limits on the endpoints that accept credentials: the token endpoint, the login form,
/// registration, and password reset.
///
/// <para>
/// Identity's account lockout caps failures against <em>one</em> account. It does nothing
/// about the two attacks that matter here: credential stuffing, where one password is tried
/// against thousands of accounts and never trips a single lockout; and resource exhaustion,
/// where unthrottled calls to the password grant are amplified by the password hasher's
/// deliberate cost into CPU starvation.
/// </para>
///
/// <para>
/// Partitioned by client IP. That key is only meaningful because
/// <see cref="ForwardedHeadersSetup"/> refuses to believe <c>X-Forwarded-For</c> from anyone
/// but the configured proxies — otherwise a caller could rotate the header for a fresh bucket
/// per request.
/// </para>
/// </summary>
public static class RateLimiting
{
    /// <summary>Endpoints that accept or issue credentials.</summary>
    public const string AuthPolicy = "auth";

    public static IServiceCollection AddAuthRateLimiting(
        this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<RateLimitingOptions>(
            configuration.GetSection(RateLimitingOptions.SectionName));

        services.AddRateLimiter(limiter =>
        {
            // Limits are read per request from options rather than captured here, so a host
            // can reconfigure them (and a test can pin them) without rebuilding the pipeline.
            limiter.AddPolicy(AuthPolicy, context =>
            {
                var settings = context.RequestServices
                    .GetRequiredService<IOptionsMonitor<RateLimitingOptions>>().CurrentValue;

                if (!settings.Enabled)
                    return RateLimitPartition.GetNoLimiter("disabled");

                return RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: PartitionKey(context),
                    factory: _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = settings.Auth.PermitLimit,
                        Window = TimeSpan.FromSeconds(settings.Auth.WindowSeconds),
                        // No queueing: a rejected credential attempt is told so immediately
                        // rather than held open occupying a connection.
                        QueueLimit = settings.Auth.QueueLimit,
                        QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    });
            });

            limiter.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

            limiter.OnRejected = (context, _) =>
            {
                var settings = context.HttpContext.RequestServices
                    .GetRequiredService<IOptionsMonitor<RateLimitingOptions>>().CurrentValue;

                // Lets a legitimate client back off correctly instead of hammering.
                context.HttpContext.Response.Headers.RetryAfter =
                    settings.Auth.WindowSeconds.ToString(CultureInfo.InvariantCulture);

                context.HttpContext.RequestServices
                    .GetRequiredService<ILoggerFactory>()
                    .CreateLogger(typeof(RateLimiting))
                    .LogWarning("Rate limit rejected {Method} {Path} from {Partition}.",
                        context.HttpContext.Request.Method,
                        context.HttpContext.Request.Path,
                        PartitionKey(context.HttpContext));

                return ValueTask.CompletedTask;
            };
        });

        return services;
    }

    /// <summary>
    /// One bucket per client address <em>per endpoint</em>.
    ///
    /// <para>
    /// The endpoint has to be part of the key. With a single bucket per address, an attacker
    /// flooding the token endpoint would also exhaust the budget for password resets and the
    /// login form from that address — turning the limiter into a denial-of-service tool
    /// against the very users it protects. That is especially sharp behind NAT, where one
    /// person's behaviour would throttle a whole office.
    /// </para>
    ///
    /// <para>
    /// Keyed on the matched endpoint rather than the raw path, so query strings cannot
    /// fragment one endpoint's bucket into unlimited separate ones.
    /// </para>
    /// </summary>
    private static string PartitionKey(HttpContext context)
    {
        // Requests with no resolvable address share a bucket rather than escaping the limit.
        var client = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var endpoint = context.GetEndpoint()?.DisplayName ?? context.Request.Path.ToString();
        return $"{client}|{endpoint}";
    }
}

public sealed class RateLimitingOptions
{
    public const string SectionName = "RateLimiting";

    /// <summary>
    /// Defaults to true. A limiter that defaults to off is a limiter that is off in
    /// production; turn it off only with another limiter in front.
    /// </summary>
    public bool Enabled { get; set; } = true;

    public AuthLimits Auth { get; set; } = new();

    public sealed class AuthLimits
    {
        public int PermitLimit { get; set; } = 20;
        public int WindowSeconds { get; set; } = 60;
        public int QueueLimit { get; set; }
    }
}
