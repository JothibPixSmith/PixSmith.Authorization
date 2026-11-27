using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using PixSmith.Authorization.API.Models;
using PixSmith.Authorization.API.Security;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using PixSmith.Authorization.Services;
using PixSmith.Authorization.Services.Interfaces;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PixSmith.Authorization.API.Controllers;

[ApiExplorerSettings(IgnoreApi = true)]
public sealed class ConnectController(
	IConnectService connectService,
	Microsoft.Extensions.Options.IOptions<RefreshTokenOptions> refreshTokens,
	TimeProvider clock) : Controller
{
	// ─── Authorization Endpoint ───────────────────────────────────────────────

	[HttpGet("~/connect/authorize")]
	[HttpPost("~/connect/authorize")]
	public async Task<IActionResult> Authorize()
	{
		var request = HttpContext.GetOpenIddictServerRequest()
			?? throw new InvalidOperationException("OpenIddict request not found.");

		var result = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);

		if (!result.Succeeded)
		{
			return Challenge(
				authenticationSchemes: IdentityConstants.ApplicationScheme,
				properties: new AuthenticationProperties
				{
					RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
						Request.HasFormContentType
							? Request.Form.ToList()
							: Request.Query.ToList())
				});
		}

		var user = await connectService.FindUserByIdentityPrincipalAsync(result.Principal!);
		if (user is null) throw new InvalidOperationException("User not found.");

		var organization = (string?)request.GetParameter("organization");

		var decision = await connectService.AuthorizeTenantAccessAsync(
			user, request.ClientId, organization);

		if (!decision.IsAllowed)
		{
			return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
			{
				[OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.AccessDenied,
				[OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = decision.Error,
			}), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
		}

		var identity = await connectService.BuildIdentityAsync(
			user, request.GetScopes(), request.ClientId, decision.Context);
		return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
	}

	// ─── Token Endpoint ───────────────────────────────────────────────────────

	[HttpPost("~/connect/token")]
	[EnableRateLimiting(RateLimiting.AuthPolicy)]
	public async Task<IActionResult> Exchange()
	{
		var request = HttpContext.GetOpenIddictServerRequest()
			?? throw new InvalidOperationException("OpenIddict request not found.");

		if (request.IsAuthorizationCodeGrantType()
			|| request.IsRefreshTokenGrantType()
			|| request.IsDeviceCodeGrantType())
		{
			var principal = (await HttpContext.AuthenticateAsync(
				OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;

			var user = await connectService.FindUserBySubjectAsync(principal!.GetClaim(Claims.Subject)!);
			if (user is null)
				return Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

			// The company travels in the principal; passing the client id lets any
			// application-scoped roles be re-resolved for this client.
			// Re-evaluated on every refresh. A membership revoked since the original
			// authorization takes effect here rather than at token expiry.
			var organization = principal!.FindFirst("org_id")?.Value;
			var decision = await connectService.AuthorizeTenantAccessAsync(
				user, request.ClientId, organization);

			if (!decision.IsAllowed)
			{
				return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
				{
					[OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.AccessDenied,
					[OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = decision.Error,
				}), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
			}

			var identity = await connectService.RefreshIdentityAsync(
				user, principal!, request.ClientId, decision.Context);

			// ── CR-8 ────────────────────────────────────────────────────────
			// The chain of refresh tokens gets an absolute deadline, counted from the grant
			// that started it and carried on the principal. Without it every refresh issued a
			// token whose lifetime started over, so a client that kept refreshing never had to
			// authenticate again — and nor did a thief who kept using a stolen refresh token.
			// Applies to this first exchange too: that is where the deadline is stamped.
			var chain = RefreshTokenPolicy.Evaluate(
				principal!, clock.GetUtcNow(), refreshTokens.Value);

			if (chain.Expired)
			{
				return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
				{
					[OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
					[OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
						"This authorization has reached its maximum lifetime. Sign in again.",
				}), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
			}

			RefreshTokenPolicy.Apply(identity, chain);

			var refreshed = new ClaimsPrincipal(identity);
			refreshed.SetRefreshTokenLifetime(chain.Lifetime);

			return SignIn(refreshed, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
		}

		if (request.IsClientCredentialsGrantType())
		{
			var identity = await connectService.BuildClientCredentialsIdentityAsync(
				request.ClientId!, request.GetScopes());
			return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
		}

		throw new InvalidOperationException($"Unsupported grant type: {request.GrantType}");
	}

	// ─── End-User Verification (device authorization grant) ──────────────────
	//
	// Where the human approves a device-flow request. The device never sees the password:
	// it polls the token endpoint while the person authenticates here in a browser. That is
	// what lets the password grant be removed without leaving non-browser callers — the
	// provisioning scripts — unable to obtain a user's token.

	[HttpGet("~/connect/verify")]
	public async Task<IActionResult> Verify()
	{
		var request = HttpContext.GetOpenIddictServerRequest()
			?? throw new InvalidOperationException("OpenIddict request not found.");

		// Sign in first: approving a device must be an authenticated act.
		var cookie = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
		if (!cookie.Succeeded)
		{
			return Challenge(
				authenticationSchemes: IdentityConstants.ApplicationScheme,
				properties: new AuthenticationProperties
				{
					RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
						Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList())
				});
		}

		// No code yet: let them type the one the device displayed.
		if (string.IsNullOrEmpty(request.UserCode))
			return View("Verify", new VerifyModel());

		// OpenIddict resolves the user code to the principal stored for that device request.
		var device = await HttpContext.AuthenticateAsync(
			OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

		if (!device.Succeeded)
		{
			return View("Verify", new VerifyModel
			{
				UserCode = request.UserCode,
				Error = "That code is not valid, or it has expired. Check the device and try again.",
			});
		}

		return View("Verify", new VerifyModel
		{
			UserCode = request.UserCode,
			ClientId = device.Principal!.GetClaim(Claims.ClientId) ?? request.ClientId,
			Scope = string.Join(" ", device.Principal!.GetScopes()),
		});
	}

	[HttpPost("~/connect/verify")]
	[ValidateAntiForgeryToken]
	public async Task<IActionResult> VerifyAccept([FromForm] VerifyModel model)
	{
		var cookie = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
		if (!cookie.Succeeded)
			return Challenge(IdentityConstants.ApplicationScheme);

		var user = await connectService.FindUserByIdentityPrincipalAsync(cookie.Principal!);
		if (user is null) throw new InvalidOperationException("User not found.");

		var device = await HttpContext.AuthenticateAsync(
			OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

		if (!device.Succeeded)
		{
			return View("Verify", new VerifyModel
			{
				UserCode = model.UserCode,
				Error = "That code is not valid, or it has expired. Check the device and try again.",
			});
		}

		var clientId = device.Principal!.GetClaim(Claims.ClientId);

		// The same tenancy decision every other grant makes. Approving at a browser must not
		// be a way around a membership or subscription the policy would refuse.
		var decision = await connectService.AuthorizeTenantAccessAsync(
			user, clientId, (string?)device.Principal!.GetClaim("org_id"));

		if (!decision.IsAllowed)
		{
			return View("Verify", new VerifyModel
			{
				UserCode = model.UserCode,
				ClientId = clientId,
				Error = decision.Error,
			});
		}

		var identity = await connectService.BuildIdentityAsync(
			user, device.Principal!.GetScopes(), clientId, decision.Context);

		// Signing in here is what marks the device code redeemable; the waiting device's next
		// poll of the token endpoint then succeeds.
		return SignIn(new ClaimsPrincipal(identity),
			new AuthenticationProperties { RedirectUri = "/connect/verify/done" },
			OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
	}

	[HttpGet("~/connect/verify/done")]
	public IActionResult VerifyDone() => View("VerifyDone");

	// ─── UserInfo Endpoint ────────────────────────────────────────────────────

	[Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
	// OIDC Core §5.3.1: the UserInfo endpoint must accept both GET and POST.
	[HttpGet("~/connect/userinfo")]
	[HttpPost("~/connect/userinfo")]
	public async Task<IActionResult> UserInfo()
	{
		var subject = User.GetClaim(Claims.Subject);
		if (subject is null)
			return Challenge(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

		var userInfo = await connectService.GetUserInfoAsync(subject);
		return userInfo is null
			? Challenge(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)
			: Ok(userInfo);
	}

	// ─── Logout Endpoint ──────────────────────────────────────────────────────

	[HttpGet("~/connect/logout")]
	public async Task<IActionResult> Logout()
	{
		var request = HttpContext.GetOpenIddictServerRequest()
			?? throw new InvalidOperationException("OpenIddict request not found.");

		// A valid id_token_hint means the relying party named the session it wants ended, so
		// honour it without interrupting the user.
		//
		// Without one, this is just a URL. Any site can navigate a signed-in user's browser
		// to it and end their SSO session — logging them out of every application at once.
		// That is a nuisance rather than a breach, but it is still an unauthenticated state
		// change driven from another origin, so it gets confirmed.
		// Both halves matter. AuthenticateAsync succeeds trivially when the request carried no
		// hint at all, so presence is checked first; the authenticate call then decides whether
		// the hint that *was* sent is actually valid.
		var hinted = !string.IsNullOrEmpty(request.IdTokenHint);

		var hint = hinted
			? await HttpContext.AuthenticateAsync(
				OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)
			: null;

		if (!hinted || hint?.Succeeded != true || hint.Principal is null)
		{
			return View("Logout", new LogoutModel
			{
				ClientId = request.ClientId,
				PostLogoutRedirectUri = request.PostLogoutRedirectUri,
				State = request.State,
			});
		}

		return await SignOutEverywhereAsync();
	}

	/// <summary>
	/// The confirmed leg. Reached from the page above, or directly by a relying party that
	/// prefers POST — the end-session endpoint accepts both.
	/// </summary>
	[HttpPost("~/connect/logout")]
	[ValidateAntiForgeryToken]
	public Task<IActionResult> LogoutPost() => SignOutEverywhereAsync();

	private async Task<IActionResult> SignOutEverywhereAsync()
	{
		await connectService.SignOutAsync();

		// RedirectUri is only a fallback: when the request carried a valid
		// post_logout_redirect_uri, OpenIddict redirects there instead.
		return SignOut(
			authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
			properties: new AuthenticationProperties { RedirectUri = "/" });
	}
}
