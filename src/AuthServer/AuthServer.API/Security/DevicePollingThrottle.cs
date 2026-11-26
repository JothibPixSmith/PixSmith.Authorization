using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace PixSmith.Authorization.API.Security;

/// <summary>
/// Answers over-fast device-code polling with <c>slow_down</c> (RFC 8628 §3.5).
///
/// <para>
/// This runs as middleware rather than in <c>ConnectController</c> because while a device code
/// is pending, OpenIddict answers <c>authorization_pending</c> from its own pipeline and the
/// controller action never executes. The check has to happen before the endpoint.
/// </para>
///
/// <para>
/// Defence in depth: the per-IP limit on <c>/connect/token</c> already bounds the damage. What
/// this adds is per-device-code pacing, which an attacker cannot sidestep by rotating source
/// addresses, and which tells a well-behaved client to back off instead of silently tolerating
/// a hot loop.
/// </para>
/// </summary>
public sealed class DevicePollingThrottle(RequestDelegate next)
{
    private const string DeviceCodeGrant = "urn:ietf:params:oauth:grant-type:device_code";

    public async Task InvokeAsync(
        HttpContext context,
        IMemoryCache cache,
        IOptions<DevicePollingOptions> options,
        ILogger<DevicePollingThrottle> logger)
    {
        var settings = options.Value;

        if (!settings.Enabled
            || !HttpMethods.IsPost(context.Request.Method)
            || !context.Request.Path.Equals("/connect/token", StringComparison.OrdinalIgnoreCase)
            || !context.Request.HasFormContentType)
        {
            await next(context);
            return;
        }

        // Buffering so the form can be read here and again by OpenIddict downstream.
        context.Request.EnableBuffering();
        var form = await context.Request.ReadFormAsync();
        context.Request.Body.Position = 0;

        if (form["grant_type"] != DeviceCodeGrant)
        {
            await next(context);
            return;
        }

        var deviceCode = form["device_code"].ToString();
        if (string.IsNullOrEmpty(deviceCode))
        {
            await next(context);
            return;
        }

        // Keyed on a hash: the device code is a bearer credential and should not sit in a
        // cache key (or a log line) in the clear.
        var key = "device-poll:" + Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(deviceCode)));

        var now = DateTimeOffset.UtcNow;
        var baseInterval = TimeSpan.FromSeconds(settings.IntervalSeconds);

        if (cache.TryGetValue<PollState>(key, out var state) && state is not null
            && now - state.LastPolledAt < state.RequiredInterval)
        {
            // RFC 8628: the client must add 5 seconds to its interval on each slow_down.
            // Tracked server-side too, so a client that ignores the instruction cannot
            // outrun the limit by continuing to hammer.
            var tightened = state.RequiredInterval + TimeSpan.FromSeconds(settings.BackoffIncrementSeconds);
            Store(cache, key, new PollState(now, tightened), settings);

            logger.LogDebug(
                "Device-code polling too fast; answering slow_down and widening the interval to {Interval}s.",
                tightened.TotalSeconds);

            await WriteSlowDownAsync(context);
            return;
        }

        Store(cache, key, new PollState(now, state?.RequiredInterval ?? baseInterval), settings);
        await next(context);
    }

    private static void Store(
        IMemoryCache cache, string key, PollState state, DevicePollingOptions settings) =>
        cache.Set(key, state, new MemoryCacheEntryOptions
        {
            // No longer than a device code can live: after that the code is dead and the
            // entry is only holding memory.
            AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(settings.StateLifetimeSeconds),
        });

    /// <summary>
    /// The error shape RFC 8628 defines, so a standards-compliant client recognises it. HTTP
    /// 400 per RFC 6749 §5.2, which is also what OpenIddict returns for authorization_pending.
    /// </summary>
    private static async Task WriteSlowDownAsync(HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        context.Response.ContentType = "application/json;charset=UTF-8";
        context.Response.Headers.CacheControl = "no-store";

        await context.Response.WriteAsync(
            """
            {"error":"slow_down","error_description":"Polling too frequently. Increase the interval by 5 seconds, per RFC 8628."}
            """);
    }

    private sealed record PollState(DateTimeOffset LastPolledAt, TimeSpan RequiredInterval);
}

public sealed class DevicePollingOptions
{
    public const string SectionName = "DevicePolling";

    public bool Enabled { get; set; } = true;

    /// <summary>
    /// The minimum gap between polls for one device code. RFC 8628 says a client that is not
    /// told otherwise assumes 5 seconds, and OpenIddict does not send an <c>interval</c> in
    /// the device authorization response, so 5 is what clients will actually use.
    /// </summary>
    public int IntervalSeconds { get; set; } = 5;

    /// <summary>Added to the required interval each time <c>slow_down</c> is returned.</summary>
    public int BackoffIncrementSeconds { get; set; } = 5;

    /// <summary>How long poll state is kept — a device code's own lifetime is the useful bound.</summary>
    public int StateLifetimeSeconds { get; set; } = 900;
}
