using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using PixSmith.Authorization.DataContext;

namespace PixSmith.Authorization.API.Security;

/// <summary>
/// Keeps authentication sessions on the server instead of in the cookie.
///
/// <para>
/// By default ASP.NET cookie authentication is entirely self-contained: the cookie *is* the
/// session. Signing out deletes the browser's copy and nothing else, so a cookie captured
/// beforehand keeps working until it expires — logout looks like it worked and did not.
/// With a session store the cookie carries only an opaque key, and
/// <see cref="RemoveAsync"/> — which the cookie handler calls on sign-out — revokes the
/// session for real.
/// </para>
///
/// <para>
/// The cost is a database read on every cookie-authenticated request. That surface is small
/// here (<c>/connect/authorize</c>, <c>/connect/verify</c>, <c>/Account/*</c>); the API and
/// protocol endpoints authenticate with bearer tokens and never touch this.
/// </para>
///
/// <para>
/// Registered as a singleton because cookie options are built once, so it resolves a scoped
/// <see cref="ApplicationDbContext"/> per operation rather than holding one.
/// </para>
/// </summary>
public sealed class EfTicketStore(
    IServiceScopeFactory scopeFactory,
    TimeProvider clock,
    ILogger<EfTicketStore> logger) : ITicketStore
{
    public async Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        // A session identifier that ends up in a cookie, so it is random rather than a Guid:
        // nothing about it should be guessable or sequential.
        var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var now = clock.GetUtcNow();

        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        db.AuthenticationTickets.Add(new AuthenticationTicketRecord
        {
            Id = key,
            Value = TicketSerializer.Default.Serialize(ticket),
            UserId = UserIdOf(ticket),
            CreatedAt = now,
            LastAccessedAt = now,
            ExpiresAt = ticket.Properties.ExpiresUtc,
        });

        await db.SaveChangesAsync();
        return key;
    }

    public async Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        var record = await db.AuthenticationTickets.SingleOrDefaultAsync(t => t.Id == key);

        if (record is null)
        {
            // Renewing a session that no longer exists would silently resurrect one that was
            // revoked, so the renewal is dropped instead of inserted.
            logger.LogDebug("Renew for an unknown session key; ignoring.");
            return;
        }

        record.Value = TicketSerializer.Default.Serialize(ticket);
        record.ExpiresAt = ticket.Properties.ExpiresUtc;
        record.LastAccessedAt = clock.GetUtcNow();

        await db.SaveChangesAsync();
    }

    public async Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        var record = await db.AuthenticationTickets
            .AsNoTracking()
            .SingleOrDefaultAsync(t => t.Id == key);

        if (record is null) return null;

        // Expiry is enforced here as well as by the cleanup sweep: a row that outlives its
        // expiry must not authenticate anyone just because the sweep has not run yet.
        if (record.ExpiresAt is { } expiry && expiry <= clock.GetUtcNow())
            return null;

        return TicketSerializer.Default.Deserialize(record.Value);
    }

    public async Task RemoveAsync(string key)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        await db.AuthenticationTickets.Where(t => t.Id == key).ExecuteDeleteAsync();
    }

    /// <summary>
    /// Revokes every session belonging to one user. Backs "sign out everywhere" directly,
    /// rather than waiting for the security stamp to be revalidated.
    /// </summary>
    public async Task<int> RemoveAllForUserAsync(Guid userId)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        return await db.AuthenticationTickets.Where(t => t.UserId == userId).ExecuteDeleteAsync();
    }

    private static Guid? UserIdOf(AuthenticationTicket ticket) =>
        Guid.TryParse(ticket.Principal.FindFirst(ClaimTypes.NameIdentifier)?.Value, out var id)
            ? id
            : null;
}
