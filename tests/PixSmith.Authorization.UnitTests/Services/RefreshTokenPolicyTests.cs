using System.Globalization;
using System.Security.Claims;
using PixSmith.Authorization.Services;
using Xunit;

namespace PixSmith.Authorization.UnitTests.Services;

/// <summary>
/// CR-8: the absolute cap on a chain of refresh tokens.
///
/// <para>
/// The arithmetic lives here because the interesting cases are about time, and waiting thirty
/// days for one of them is not an option. The integration suite covers the seam — that the
/// token endpoint actually consults this and that the deadline survives a round trip through a
/// refresh token.
/// </para>
/// </summary>
public sealed class RefreshTokenPolicyTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 11, 27, 12, 0, 0, TimeSpan.Zero);

    private static ClaimsPrincipal WithDeadline(DateTimeOffset deadline) =>
        new(new ClaimsIdentity([new Claim(
            RefreshTokenPolicy.DeadlineClaim,
            deadline.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture))]));

    private static ClaimsPrincipal WithNoDeadline() => new(new ClaimsIdentity());

    [Fact]
    public void A_new_grant_starts_the_clock()
    {
        // No claim yet: this is the first exchange, so the deadline is the full cap from now.
        var options = new RefreshTokenOptions { AbsoluteLifetimeSeconds = 3600 };

        var decision = RefreshTokenPolicy.Evaluate(WithNoDeadline(), Now, options);

        Assert.False(decision.Expired);
        Assert.Equal(Now.AddSeconds(3600), decision.Deadline);
    }

    [Fact]
    public void A_refresh_inside_the_cap_keeps_the_original_deadline()
    {
        // The whole point: the deadline does not move because time has passed.
        var deadline = Now.AddDays(20);
        var options = new RefreshTokenOptions();

        var decision = RefreshTokenPolicy.Evaluate(WithDeadline(deadline), Now, options);

        Assert.False(decision.Expired);
        Assert.Equal(deadline, decision.Deadline);
    }

    [Fact]
    public void A_refresh_past_the_deadline_is_expired()
    {
        var decision = RefreshTokenPolicy.Evaluate(
            WithDeadline(Now.AddSeconds(-1)), Now, new RefreshTokenOptions());

        Assert.True(decision.Expired);
        Assert.Equal(TimeSpan.Zero, decision.Lifetime);
    }

    [Fact]
    public void The_deadline_itself_is_not_a_grace_period()
    {
        // Exactly at the deadline is expired, not the last valid instant.
        var decision = RefreshTokenPolicy.Evaluate(
            WithDeadline(Now), Now, new RefreshTokenOptions());

        Assert.True(decision.Expired);
    }

    [Fact]
    public void The_idle_timeout_applies_while_there_is_room_for_it()
    {
        var options = new RefreshTokenOptions
        {
            AbsoluteLifetimeSeconds = 2_592_000,   // 30 days
            SlidingLifetimeSeconds = 1_209_600,    // 14 days
        };

        var decision = RefreshTokenPolicy.Evaluate(
            WithDeadline(Now.AddDays(30)), Now, options);

        Assert.Equal(TimeSpan.FromDays(14), decision.Lifetime);
    }

    [Fact]
    public void The_last_token_of_a_chain_is_cut_short_by_the_cap()
    {
        // Two days left but a fourteen-day idle timeout: the token must not outlive the cap,
        // which is what makes the deadline enforceable by expiry as well as by the check.
        var options = new RefreshTokenOptions
        {
            AbsoluteLifetimeSeconds = 2_592_000,
            SlidingLifetimeSeconds = 1_209_600,
        };

        var decision = RefreshTokenPolicy.Evaluate(
            WithDeadline(Now.AddDays(2)), Now, options);

        Assert.Equal(TimeSpan.FromDays(2), decision.Lifetime);
    }

    [Fact]
    public void A_zero_idle_timeout_pins_the_token_to_the_deadline()
    {
        // The setting that makes exp identical before and after a refresh.
        var options = new RefreshTokenOptions
        {
            AbsoluteLifetimeSeconds = 2_592_000,
            SlidingLifetimeSeconds = 0,
        };

        var decision = RefreshTokenPolicy.Evaluate(
            WithDeadline(Now.AddDays(9)), Now, options);

        Assert.Equal(TimeSpan.FromDays(9), decision.Lifetime);
    }

    [Fact]
    public void A_non_positive_cap_falls_back_to_the_default_rather_than_switching_off()
    {
        // An absolute expiry that a typo can disable is not a control. Zero must not mean
        // "unlimited" — that reading is conventional for timeouts and wrong for this one.
        var decision = RefreshTokenPolicy.Evaluate(
            WithNoDeadline(), Now, new RefreshTokenOptions { AbsoluteLifetimeSeconds = 0 });

        Assert.False(decision.Expired);
        Assert.Equal(Now.AddSeconds(new RefreshTokenOptions().AbsoluteLifetimeSeconds),
            decision.Deadline);
    }

    [Fact]
    public void A_garbled_deadline_claim_is_treated_as_absent()
    {
        // Rather than throwing on a value this server did not write.
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(RefreshTokenPolicy.DeadlineClaim, "not-a-number")]));

        var decision = RefreshTokenPolicy.Evaluate(
            principal, Now, new RefreshTokenOptions { AbsoluteLifetimeSeconds = 60 });

        Assert.False(decision.Expired);
        Assert.Equal(Now.AddSeconds(60), decision.Deadline);
    }

    [Fact]
    public void Apply_writes_the_deadline_the_next_exchange_will_read()
    {
        // Round-trips through the claim, which is the mechanism: nothing is stored server-side
        // to remember when the chain began.
        var identity = new ClaimsIdentity();
        var deadline = Now.AddDays(11);

        RefreshTokenPolicy.Apply(identity, new RefreshTokenPolicy.Decision(
            false, deadline, TimeSpan.FromDays(11)));

        var reread = RefreshTokenPolicy.Evaluate(
            new ClaimsPrincipal(identity), Now, new RefreshTokenOptions());

        Assert.Equal(deadline, reread.Deadline);
    }
}
