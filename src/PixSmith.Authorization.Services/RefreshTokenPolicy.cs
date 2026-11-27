using System.Globalization;
using System.Security.Claims;
using OpenIddict.Abstractions;

namespace PixSmith.Authorization.Services;

/// <summary>
/// How long a chain of refresh tokens may live, counted from the grant that started it.
/// </summary>
public sealed class RefreshTokenOptions
{
    public const string SectionName = "RefreshTokens";

    /// <summary>
    /// The hard cap, from the original grant. Once it runs out the refresh is refused and the
    /// user has to authenticate again — no amount of refreshing extends it. A value of zero or
    /// less falls back to the default rather than removing the cap: an absolute expiry that can
    /// be switched off by a typo is not a control. To keep refresh tokens alive for a long time
    /// deliberately, set a long value.
    /// </summary>
    public int AbsoluteLifetimeSeconds { get; set; } = 2_592_000;   // 30 days

    /// <summary>
    /// The idle timeout: how long any one refresh token lasts if it is never used. Each refresh
    /// issues a token with this lifetime, shortened to whatever is left of the absolute cap.
    /// The default matches OpenIddict's own, so the sliding behaviour is unchanged.
    ///
    /// <para>
    /// Zero pins every refresh token to the absolute deadline instead, so its expiry is
    /// identical before and after a refresh. That is what a conformance check looking for an
    /// unmoving <c>exp</c> expects, at the cost of the idle timeout: a token untouched for 29
    /// days would still work on day 30.
    /// </para>
    /// </summary>
    public int SlidingLifetimeSeconds { get; set; } = 1_209_600;    // 14 days
}

/// <summary>
/// CR-8: refresh tokens must reach an absolute expiry (ASVS 10.4.8).
///
/// <para>
/// OpenIddict issues each refresh token with a lifetime counted from the moment it is created,
/// so a client that keeps refreshing never has to authenticate again — and a stolen refresh
/// token that keeps being used stays valid for as long as the thief keeps using it. The sliding
/// window alone only ever punishes going idle.
/// </para>
///
/// <para>
/// The deadline is carried on the principal as a claim, which is why this works at all: the
/// claim is written into the refresh token, comes back on the next exchange, and is handed
/// forward unchanged. Nothing has to be stored server-side to remember when the chain started.
/// The claim is given no destination (see <c>ConnectService.GetDestinations</c>) so it stays
/// inside the refresh token and is never published in an access or identity token.
/// </para>
/// </summary>
public static class RefreshTokenPolicy
{
    /// <summary>
    /// Unix seconds. Deliberately not an <c>oi_</c> name: that prefix is OpenIddict's own and
    /// its claims are stripped before a token is written.
    /// </summary>
    public const string DeadlineClaim = "refresh_expires_at";

    /// <param name="Expired">The chain has reached its absolute expiry; refuse the exchange.</param>
    /// <param name="Deadline">The absolute deadline to carry forward.</param>
    /// <param name="Lifetime">What the next refresh token gets: the idle timeout, or what is
    /// left of the cap, whichever is shorter.</param>
    public sealed record Decision(bool Expired, DateTimeOffset Deadline, TimeSpan Lifetime);

    public static Decision Evaluate(
        ClaimsPrincipal principal, DateTimeOffset now, RefreshTokenOptions options)
    {
        var absolute = TimeSpan.FromSeconds(options.AbsoluteLifetimeSeconds > 0
            ? options.AbsoluteLifetimeSeconds
            : new RefreshTokenOptions().AbsoluteLifetimeSeconds);

        // No claim means this is the first exchange of a fresh grant — or a refresh token
        // issued before this cap existed. Starting the clock now grandfathers the second case
        // instead of logging those users out on deploy; the window that creates is bounded by
        // the rollout, and every token minted afterwards carries the deadline.
        var deadline = ReadDeadline(principal) ?? now + absolute;

        if (deadline <= now) return new Decision(true, deadline, TimeSpan.Zero);

        var remaining = deadline - now;
        var sliding = options.SlidingLifetimeSeconds > 0
            ? TimeSpan.FromSeconds(options.SlidingLifetimeSeconds)
            : remaining;

        return new Decision(false, deadline, remaining < sliding ? remaining : sliding);
    }

    /// <summary>Writes the deadline onto the identity that will become the new principal.</summary>
    public static void Apply(ClaimsIdentity identity, Decision decision) =>
        identity.SetClaim(
            DeadlineClaim,
            decision.Deadline.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture));

    private static DateTimeOffset? ReadDeadline(ClaimsPrincipal principal) =>
        long.TryParse(
            principal.FindFirst(DeadlineClaim)?.Value,
            NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : null;
}
