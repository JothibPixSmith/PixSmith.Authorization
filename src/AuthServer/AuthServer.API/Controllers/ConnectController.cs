using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using PixSmith.Authorization.Services.Interfaces;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PixSmith.Authorization.API.Controllers;

[ApiExplorerSettings(IgnoreApi = true)]
public sealed class ConnectController(IConnectService connectService) : Controller
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

		var identity = await connectService.BuildIdentityAsync(user, request.GetScopes());
		return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
	}

	// ─── Token Endpoint ───────────────────────────────────────────────────────

	[HttpPost("~/connect/token")]
	public async Task<IActionResult> Exchange()
	{
		var request = HttpContext.GetOpenIddictServerRequest()
			?? throw new InvalidOperationException("OpenIddict request not found.");

		if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
		{
			var principal = (await HttpContext.AuthenticateAsync(
				OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;

			var user = await connectService.FindUserBySubjectAsync(principal!.GetClaim(Claims.Subject)!);
			if (user is null)
				return Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

			var identity = await connectService.RefreshIdentityAsync(user, principal!);
			return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
		}

		if (request.IsPasswordGrantType())
		{
			var user = await connectService.FindUserByUsernameAsync(request.Username!);
			if (user is null)
				return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
				{
					[OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
					[OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Invalid credentials."
				}), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

			var validation = await connectService.ValidatePasswordAsync(user, request.Password!);
			if (!validation.IsSuccess)
				return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
				{
					[OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
					[OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = validation.Error
				}), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

			var identity = await connectService.BuildIdentityAsync(user, request.GetScopes());
			return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
		}

		if (request.IsClientCredentialsGrantType())
		{
			var identity = await connectService.BuildClientCredentialsIdentityAsync(
				request.ClientId!, request.GetScopes());
			return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
		}

		throw new InvalidOperationException($"Unsupported grant type: {request.GrantType}");
	}

	// ─── UserInfo Endpoint ────────────────────────────────────────────────────

	[Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
	[HttpGet("~/connect/userinfo")]
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
		await connectService.SignOutAsync();
		return SignOut(
			authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
			properties: new AuthenticationProperties { RedirectUri = "/" });
	}
}
