using System.Net;
using System.Net.Http.Headers;

namespace PixSmith.Authorization.BlazorClient.Services;

/// <summary>
/// Delegating handler that attaches the stored access token to every outgoing request and
/// proactively refreshes it when the expiry threshold is reached.
///
/// Refresh is guarded by a semaphore so that multiple concurrent requests expiring at the
/// same time only trigger one refresh round-trip — subsequent waiters re-check expiry after
/// the lock is released and skip the refresh if the first waiter already renewed the token.
/// </summary>
public sealed class JwtTokenHandler(JwtAuthStateProvider authProvider) : DelegatingHandler
{
    private static readonly SemaphoreSlim _refreshLock = new(1, 1);

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // Proactive refresh: if the stored token is at or past its expiry threshold,
        // refresh before sending so the request succeeds on the first attempt.
        if (await authProvider.IsTokenExpiredAsync())
        {
            await _refreshLock.WaitAsync(cancellationToken);
            try
            {
                // Re-check inside the lock — a concurrent request may have already refreshed.
                if (await authProvider.IsTokenExpiredAsync())
                    await authProvider.RefreshAsync();
            }
            finally
            {
                _refreshLock.Release();
            }
        }

        var token = await authProvider.GetAccessTokenAsync();
        if (!string.IsNullOrEmpty(token))
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        return await base.SendAsync(request, cancellationToken);
    }
}
