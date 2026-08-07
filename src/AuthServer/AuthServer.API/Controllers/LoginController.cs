using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PixSmith.Authorization.API.Models;

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
/// the Blazor admin UI over the password grant and never establishes a cookie session.
/// </para>
/// </summary>
[ApiExplorerSettings(IgnoreApi = true)]
[AllowAnonymous]
public sealed class LoginController(
	SignInManager<IdentityUser<Guid>> signInManager,
	UserManager<IdentityUser<Guid>> userManager,
	ILogger<LoginController> logger) : Controller
{
	[HttpGet("~/Account/Login")]
	public IActionResult Index(string? returnUrl = null) =>
		View(new LoginInputModel { ReturnUrl = SafeReturnUrl(returnUrl) });

	[HttpPost("~/Account/Login")]
	[ValidateAntiForgeryToken]
	public async Task<IActionResult> Index(LoginInputModel model)
	{
		model.ReturnUrl = SafeReturnUrl(model.ReturnUrl);

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

	[HttpPost("~/Account/Logout")]
	[ValidateAntiForgeryToken]
	public async Task<IActionResult> Logout(string? returnUrl = null)
	{
		await signInManager.SignOutAsync();
		return Redirect(SafeReturnUrl(returnUrl) ?? "/");
	}

	[HttpGet("~/Account/AccessDenied")]
	public IActionResult AccessDenied() => View();

	/// <summary>
	/// Drops non-local return URLs so a crafted link cannot turn the login page into an
	/// open redirect. Client redirect URIs are validated separately by OpenIddict.
	/// </summary>
	private string? SafeReturnUrl(string? returnUrl) =>
		!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl) ? returnUrl : null;
}
