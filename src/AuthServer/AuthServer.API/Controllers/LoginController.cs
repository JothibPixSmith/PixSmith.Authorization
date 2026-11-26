using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Mvc;
using PixSmith.Authorization.API.Models;
using PixSmith.Authorization.Repositories.Interfaces;

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
	ILogger<LoginController> logger) : Controller
{
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
			// Same message as a bad password so the form does not disclose which emails exist.
			ModelState.AddModelError(string.Empty, "Invalid email or password.");
			return View(model);
		}

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

		ModelState.AddModelError(string.Empty, result switch
		{
			{ IsLockedOut: true }  => "This account is locked out. Try again later.",
			{ IsNotAllowed: true } => "Please confirm your email address before signing in.",
			_                      => "Invalid email or password.",
		});

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
