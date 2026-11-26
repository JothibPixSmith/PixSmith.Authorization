using OpenIddict.Abstractions;

namespace PixSmith.Authorization.API.Security;

/// <summary>
/// Revokes every OAuth credential a user holds — refresh tokens, access-token entries,
/// authorization and device codes, and the authorizations they hang off.
///
/// <para>
/// This is the other half of "sign out everywhere". <see cref="EfTicketStore"/> closes the
/// cookie session, but a cookie is only one of three credentials in play. Access tokens are
/// self-contained JWTs validated against the signing key, and refresh tokens were left
/// untouched entirely: a holder could present one *after* the logout and be handed a fresh
/// access token, then keep doing that for the refresh token's whole lifetime. Signing out
/// everywhere therefore ended the browser's session and nothing else.
/// </para>
///
/// <para>
/// Refresh tokens are validated against storage on every redemption, so marking the entries
/// revoked kills them at the next attempt and costs nothing per request — unlike access-token
/// entry validation, which would add a database read to every API call. That asymmetry is why
/// this closes the unbounded window while the access-token window (its lifetime, one hour by
/// default) necessarily stays open. Shortening that lifetime is the only lever that narrows it
/// without paying per request.
/// </para>
/// </summary>
public sealed class TokenRevocation(
	IOpenIddictTokenManager tokens,
	IOpenIddictAuthorizationManager authorizations,
	ILogger<TokenRevocation> logger)
{
	/// <summary>What was revoked, for the audit line.</summary>
	public sealed record Revoked(int Tokens, int Authorizations);

	public async Task<Revoked> RevokeAllForUserAsync(Guid userId, CancellationToken ct = default)
	{
		// The subject claim is the Identity user id as a string — see ConnectService, which
		// sets it from UserManager.GetUserIdAsync.
		var subject = userId.ToString();

		// Authorizations first, deliberately. A refresh already in flight validates both the
		// token entry and the authorization it belongs to; revoking authorizations first means
		// a request that slips past the token sweep is still refused, rather than minting a new
		// token against a consent we are in the middle of withdrawing.
		var authorizationCount = 0;
		foreach (var authorization in await CollectAsync(authorizations.FindBySubjectAsync(subject, ct)))
		{
			if (await authorizations.TryRevokeAsync(authorization, ct))
				authorizationCount++;
		}

		var tokenCount = 0;
		foreach (var token in await CollectAsync(tokens.FindBySubjectAsync(subject, ct)))
		{
			if (await tokens.TryRevokeAsync(token, ct))
				tokenCount++;
		}

		logger.LogInformation(
			"Revoked {Tokens} token(s) and {Authorizations} authorization(s) for user {UserId}.",
			tokenCount, authorizationCount, userId);

		return new Revoked(tokenCount, authorizationCount);
	}

	/// <summary>
	/// Materialises the query before revoking anything. The managers share the request's
	/// DbContext, and revoking saves changes — doing that while a streaming result is still
	/// open on the same context is the classic "a second operation was started" failure.
	/// </summary>
	private static async Task<List<object>> CollectAsync(IAsyncEnumerable<object> source)
	{
		var items = new List<object>();
		await foreach (var item in source)
			items.Add(item);

		return items;
	}
}
