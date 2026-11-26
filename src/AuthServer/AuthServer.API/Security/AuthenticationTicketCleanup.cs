using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using PixSmith.Authorization.DataContext;

namespace PixSmith.Authorization.API.Security;

/// <summary>
/// Deletes expired server-side sessions.
///
/// <para>
/// Needed because a session store only grows otherwise: every sign-in adds a row and nothing
/// removes the ones that lapse rather than being signed out of. Expired rows never
/// authenticate anyone — <see cref="EfTicketStore.RetrieveAsync"/> checks expiry too — so this
/// is housekeeping, not a security control.
/// </para>
/// </summary>
public sealed class AuthenticationTicketCleanup(
    IServiceScopeFactory scopeFactory,
    IOptions<ServerSessionOptions> options,
    TimeProvider clock,
    ILogger<AuthenticationTicketCleanup> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromMinutes(Math.Max(1, options.Value.CleanupIntervalMinutes));

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var scope = scopeFactory.CreateAsyncScope();
                var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

                var cutoff = clock.GetUtcNow();
                var removed = await db.AuthenticationTickets
                    .Where(t => t.ExpiresAt != null && t.ExpiresAt <= cutoff)
                    .ExecuteDeleteAsync(stoppingToken);

                if (removed > 0)
                    logger.LogDebug("Removed {Count} expired authentication session(s).", removed);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Housekeeping must never take the host down.
                logger.LogError(ex, "Expired-session cleanup failed; will retry.");
            }

            try
            {
                await Task.Delay(interval, clock, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }
}

/// <summary>Settings for the server-side session store.</summary>
public sealed class ServerSessionOptions
{
    public const string SectionName = "Sessions";

    public int CleanupIntervalMinutes { get; set; } = 15;

    /// <summary>
    /// How often a cookie's security stamp is revalidated against the database. This is what
    /// makes "sign out everywhere" and a password change take effect on sessions other than
    /// the current one. Zero would revalidate on every request; the ticket store already
    /// revokes the signing-out session immediately, so this only bounds how long *other*
    /// devices keep working after a deliberate global sign-out.
    /// </summary>
    public int SecurityStampValidationMinutes { get; set; } = 5;
}
