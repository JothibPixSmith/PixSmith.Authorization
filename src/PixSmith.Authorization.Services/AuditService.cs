using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Services.Interfaces;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PixSmith.Authorization.Services;

public sealed class AuditService(
    ApplicationDbContext db,
    IHttpContextAccessor httpContextAccessor,
    ILogger<AuditService> logger) : IAuditService
{
    public async Task RecordAsync(string action, string? details = null, CancellationToken ct = default)
    {
        var http = httpContextAccessor.HttpContext;

        // A machine-to-machine token's subject is a client id, not a user id, so it will not
        // parse — the entry is still written, just without a user attribution.
        Guid? userId = Guid.TryParse(http?.User.FindFirst(Claims.Subject)?.Value, out var parsed)
            ? parsed
            : null;

        try
        {
            db.AuditLogs.Add(new AuditLog
            {
                Id         = Guid.NewGuid(),
                UserId     = userId,
                Action     = action,
                Details    = details,
                IpAddress  = http?.Connection.RemoteIpAddress?.ToString(),
                OccurredAt = DateTimeOffset.UtcNow,
            });

            await db.SaveChangesAsync(ct);
        }
        catch (Exception ex)
        {
            // Deliberately swallowed. The action it describes has already happened; failing the
            // request now would tell the caller it did not, which is worse than a missing row.
            // The log line is the backstop.
            logger.LogError(ex,
                "Failed to write audit entry {Action} for user {UserId}. Details: {Details}",
                action, userId, details);
        }
    }
}
