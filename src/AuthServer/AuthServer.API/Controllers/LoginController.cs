using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Mvc;
using PixSmith.Authorization.API.Models;
using PixSmith.Authorization.Repositories.Interfaces;
using PixSmith.Authorization.Services.Interfaces;

namespace PixSmith.Authorization.API.Controllers;

/// <summary>
/// Server-rendered login UI that backs the interactive authorization code flow.
///
/// <para>
/// <c>ConnectController.Authorize</c> challenges <see cref="IdentityConstants.ApplicationScheme"/>
/// when the caller has no session; the cookie handler redirects here with a ReturnUrl pointing
/// back at <c>/connect/authorize</c>. Signing in here issues the Identity application cookie —
/// the shared SSO session — after which the authorize endpoint can mint an authorization code.
/// </para>
///
/// <para>
/// This is deliberately separate from <c>AccountController</c>, which is a JSON API consumed by
/// the Blazor admin UI with a bearer token and never establishes a cookie session.
/// </para>
/// </summary>
[ApiExplorerSettings(IgnoreApi = true)]
[AllowAnonymous]
public sealed class LoginController(
	SignInManager<IdentityUser<Guid>> signInManager,
	UserManager<IdentityUser<Guid>> userManager,
	ITenantRepository tenants,
	Security.EfTicketStore ticketStore,
	Security.TokenRevocation revocation,
	Security.DummyPasswordVerifier dummyPassword,
	IEmailService emails,
	IConfiguration configuration,
	TimeProvider clock,
	ILogger<LoginController> logger) : Controller
{
	/// <summary>
	/// The only thing a failed sign-in ever says. One wording for "no such account", "wrong
	/// password" and "locked out": each of the others would tell an attacker which addresses
	/// are worth attacking, and the first two have to match for the lockout wording to be
	/// worth anything at all.
	/// </summary>
	private const string GenericFailure = "Invalid email or password.";

	[HttpGet("~/Account/Login")]
	public async Task<IActionResult> Index(string? returnUrl = null)
	{
		var safe = SafeReturnUrl(returnUrl);

		return View(new LoginInputModel
		{
			ReturnUrl = safe,
			OrganizationName = await ResolveOrganizationNameAsync(safe),
		});
	}

	[HttpPost("~/Account/Login")]
	[ValidateAntiForgeryToken]
	[EnableRateLimiting(Security.RateLimiting.AuthPolicy)]
	public async Task<IActionResult> Index(LoginInputModel model)
	{
		model.ReturnUrl = SafeReturnUrl(model.ReturnUrl);
		model.OrganizationName = await ResolveOrganizationNameAsync(model.ReturnUrl);

		if (!ModelState.IsValid)
			return View(model);

		// Identity's user store is keyed on username; the login form asks for an email.
		var user = await userManager.FindByEmailAsync(model.Email)
			?? await userManager.FindByNameAsync(model.Email);

		if (user is null)
		{
			// Verify the password against a throwaway hash before answering. Returning here
			// without hashing anything made an unknown address answer in about 4 ms against a
			// real account's 72 ms, which enumerates accounts just as well as a different
			// message does. See DummyPasswordVerifier.
			dummyPassword.Verify(model.Password);

			ModelState.AddModelError(string.Empty, GenericFailure);
			return View(model);
		}

		// Read before the attempt. Identity answers LockedOut both for the attempt that trips
		// the lock and for every attempt afterwards, so comparing before with after is the only
		// way to notify the owner once rather than on every retry.
		var wasLockedOut = await userManager.GetLockoutEndDateAsync(user) > clock.GetUtcNow();

		var result = await signInManager.PasswordSignInAsync(
			user, model.Password, model.RememberMe, lockoutOnFailure: true);

		if (result.Succeeded)
		{
			logger.LogInformation("User {UserId} signed in via the hosted login page.", user.Id);
			return Redirect(model.ReturnUrl ?? "/");
		}

		if (result.RequiresTwoFactor)
		{
			// The domain tracks 2FA state but no second-factor UI exists yet; fail closed
			// rather than silently completing the sign-in without the second factor.
			ModelState.AddModelError(string.Empty,
				"Two-factor authentication is required for this account but is not yet supported here.");
			return View(model);
		}

		if (result.IsLockedOut)
		{
			if (wasLockedOut)
			{
				// Identity refuses an account that is already locked before it verifies
				// anything, so this answer would come back in milliseconds against the 70-odd
				// a wrong password costs — the oracle the shared wording is there to close.
				dummyPassword.Verify(model.Password);
			}
			else
			{
				// The attempt that tripped the lock. It verified a real password on the way,
				// so it has already paid; what it owes is the notice to the account's owner.
				await NotifyLockedOutAsync(user);
			}
		}

		if (result.IsNotAllowed)
		{
			if (!user.EmailConfirmed)
			{
				// Verifies the password itself, and sends a fresh link if it was right.
				await ReconfirmEmailAsync(user, model.Password);
			}
			else
			{
				// Some other CanSignInAsync rule — a confirmed phone number, say. None is
				// configured today, so this is unreachable; it is here because the invariant
				// is that every way out of this form verifies a password exactly once, and
				// the next rule somebody enables should not quietly break it.
				dummyPassword.Verify(model.Password);
			}
		}

		// One wording, for every way this can fail: no such account, a wrong password, a
		// locked-out account, and an address that was never confirmed. Each of the others gets
		// told what it needs by email instead.
		ModelState.AddModelError(string.Empty, GenericFailure);

		return View(model);
	}

	/// <summary>
	/// Ends this session. The cookie handler deletes the server-side ticket as part of
	/// sign-out, so the session is revoked rather than merely forgotten by the browser —
	/// a cookie captured beforehand stops working immediately.
	/// </summary>
	[HttpPost("~/Account/Logout")]
	[ValidateAntiForgeryToken]
	public async Task<IActionResult> Logout(string? returnUrl = null)
	{
		await signInManager.SignOutAsync();
		return Redirect(SafeReturnUrl(returnUrl) ?? "/");
	}

	/// <summary>
	/// Ends every session this user has anywhere — the "I think someone else is signed in as
	/// me" action.
	///
	/// <para>
	/// Three credentials, all of them deliberate. Deleting the tickets revokes existing
	/// sessions at once; rotating the security stamp invalidates any cookie still in flight and
	/// stops a captured one being reused, which deleting the rows alone cannot guarantee for a
	/// session created in the same instant; and revoking the OAuth tokens is what keeps a
	/// refresh token from outliving the logout entirely.
	/// </para>
	///
	/// <para>
	/// One window remains and cannot be closed here: an access token already issued is a signed
	/// JWT validated against the key, so it stays good until it expires (an hour by default).
	/// Closing that too means validating token entries on every API request — a database read
	/// per call. See TokenRevocation.
	/// </para>
	/// </summary>
	[HttpPost("~/Account/LogoutEverywhere")]
	[ValidateAntiForgeryToken]
	public async Task<IActionResult> LogoutEverywhere(string? returnUrl = null)
	{
		// Authenticated explicitly: the Identity cookie is no longer the default scheme, so
		// HttpContext.User is not it. Reading User here would find nothing and revoke
		// nothing — silently, which is the worst way for this to fail.
		var cookie = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
		var user = cookie.Succeeded && cookie.Principal is not null
			? await userManager.GetUserAsync(cookie.Principal)
			: null;

		if (user is not null)
		{
			var revoked = await ticketStore.RemoveAllForUserAsync(user.Id);
			await userManager.UpdateSecurityStampAsync(user);

			// Tokens as well as sessions. Refresh tokens are checked against storage when they
			// are redeemed, so this takes effect on the next attempt rather than at expiry.
			var credentials = await revocation.RevokeAllForUserAsync(
				user.Id, HttpContext.RequestAborted);

			logger.LogInformation(
				"User {UserId} signed out everywhere; {Sessions} session(s), {Tokens} token(s) "
				+ "and {Authorizations} authorization(s) revoked.",
				user.Id, revoked, credentials.Tokens, credentials.Authorizations);
		}

		await signInManager.SignOutAsync();
		return Redirect(SafeReturnUrl(returnUrl) ?? "/");
	}

	[HttpGet("~/Account/AccessDenied")]
	public IActionResult AccessDenied() => View();

	/// <summary>
	/// Tells the account's owner that it has been locked, since the page no longer can.
	///
	/// <para>
	/// Sent once, on the attempt that trips the lock, and only to the address on the account —
	/// so it reaches whoever owns it and nobody who is guessing at it. Enqueued through the
	/// outbox like every other message; a failure here is logged and swallowed, because a
	/// mail problem must not turn a refused sign-in into a 500.
	/// </para>
	/// </summary>
	private async Task NotifyLockedOutAsync(IdentityUser<Guid> user)
	{
		if (user.Email is null or { Length: 0 }) return;

		var lockoutEnd = await userManager.GetLockoutEndDateAsync(user) ?? clock.GetUtcNow();

		try
		{
			await emails.SendAccountLockedAsync(
				user.Email, lockoutEnd, $"{FrontendBaseUri()}/forgot-password",
				HttpContext.RequestAborted);

			logger.LogInformation(
				"Account {UserId} locked out until {LockoutEnd}; the owner was notified by email.",
				user.Id, lockoutEnd);
		}
		catch (Exception ex)
		{
			logger.LogError(ex,
				"Account {UserId} was locked out but the notification could not be queued.",
				user.Id);
		}
	}

	/// <summary>
	/// Hands a fresh confirmation link to an account that has never confirmed its address —
	/// and only when the password submitted was the right one.
	///
	/// <para>
	/// The page used to answer this case with "Please confirm your email address before
	/// signing in.", which is the one message that undid the rest of the work here: every
	/// account starts out unconfirmed, so that reply told anyone willing to try a wrong
	/// password that the address was registered. Saying nothing would leave the real user
	/// stuck at a page insisting their password is wrong, so they are told the one way that
	/// reaches them and nobody else.
	/// </para>
	///
	/// <para>
	/// Gated on the password being correct for two reasons. It is the evidence that this is
	/// the account's owner rather than somebody working through a list — and without it a run
	/// of guesses would become a way to flood that owner's inbox. Verifying it also costs a
	/// PBKDF2 hash, which is what keeps this path's timing in line with the rest: Identity
	/// refuses an unconfirmed account before it verifies anything, so nothing else here would.
	/// </para>
	/// </summary>
	private async Task ReconfirmEmailAsync(IdentityUser<Guid> user, string password)
	{
		var correct = await userManager.CheckPasswordAsync(user, password);
		if (!correct || user.Email is null or { Length: 0 }) return;

		try
		{
			var token = await userManager.GenerateEmailConfirmationTokenAsync(user);
			var link = $"{FrontendBaseUri()}/confirm-email"
				+ $"?email={Uri.EscapeDataString(user.Email)}"
				+ $"&token={Uri.EscapeDataString(token)}";

			await emails.SendEmailConfirmationReminderAsync(
				user.Email, link, HttpContext.RequestAborted);

			logger.LogInformation(
				"User {UserId} signed in with the right password but has not confirmed their "
				+ "address; a fresh confirmation link was sent.", user.Id);
		}
		catch (Exception ex)
		{
			logger.LogError(ex,
				"Could not queue a confirmation link for {UserId}.", user.Id);
		}
	}

	/// <summary>
	/// Where the admin UI is served from — the base the registration and password-reset mails
	/// are built against too — falling back to this request's own origin when it is not
	/// configured, so a link is never built against nothing.
	/// </summary>
	private string FrontendBaseUri() =>
		(configuration["OpenIddict:BlazorClient:BaseUri"] is { Length: > 0 } configured
			? configured
			: $"{Request.Scheme}://{Request.Host}").TrimEnd('/');

	/// <summary>
	/// Reads the <c>organization</c> parameter the calling application put on its authorization
	/// request — it survives inside ReturnUrl — and resolves it to a real tenancy.
	///
	/// <para>
	/// Resolving against the database rather than echoing the parameter is the point: the page
	/// can only ever name a company that exists, so a crafted link cannot make it claim to be
	/// signing the user in to somewhere it is not.
	/// </para>
	/// </summary>
	private async Task<string?> ResolveOrganizationNameAsync(string? returnUrl)
	{
		if (string.IsNullOrWhiteSpace(returnUrl)) return null;

		var query = returnUrl.IndexOf('?');
		if (query < 0) return null;

		var requested = Microsoft.AspNetCore.WebUtilities.QueryHelpers
			.ParseQuery(returnUrl[query..])
			.TryGetValue("organization", out var values) ? values.FirstOrDefault() : null;

		if (string.IsNullOrWhiteSpace(requested)) return null;

		var all = await tenants.GetAllAsync(HttpContext.RequestAborted);

		var match = all.FirstOrDefault(t =>
			t.IsActive
			&& (string.Equals(t.Slug, requested, StringComparison.OrdinalIgnoreCase)
				|| (Guid.TryParse(requested, out var id) && t.Id == id)));

		return match?.Name;
	}

	/// <summary>
	/// Drops non-local return URLs so a crafted link cannot turn the login page into an
	/// open redirect. Client redirect URIs are validated separately by OpenIddict.
	/// </summary>
	private string? SafeReturnUrl(string? returnUrl) =>
		!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl) ? returnUrl : null;
}
