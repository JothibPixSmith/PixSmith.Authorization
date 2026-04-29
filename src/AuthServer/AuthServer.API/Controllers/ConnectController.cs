using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthServer.API.Controllers;

/// <summary>
/// Handles all OAuth 2.0 / OIDC protocol endpoints:
///   GET  /connect/authorize  - Authorization endpoint
///   POST /connect/token      - Token endpoint
///   GET  /connect/userinfo   - UserInfo endpoint
///   GET  /connect/logout     - Logout endpoint
/// </summary>
[ApiExplorerSettings(IgnoreApi = true)] // Hide from Swagger - these are protocol endpoints
public sealed class ConnectController(
	IOpenIddictApplicationManager applicationManager,
	IOpenIddictScopeManager scopeManager,
	UserManager<IdentityUser<Guid>> userManager,
	SignInManager<IdentityUser<Guid>> signInManager) : Controller
{
	// ─── Authorization Endpoint ───────────────────────────────────────────

	[HttpGet("~/connect/authorize")]
	[HttpPost("~/connect/authorize")]
	public async Task<IActionResult> Authorize()
	{
		var request = HttpContext.GetOpenIddictServerRequest()
			?? throw new InvalidOperationException("OpenIddict request not found.");

		// Try to retrieve the existing user principal
		var result = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);

		if (!result.Succeeded)
		{
			// Not authenticated - redirect to login page
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

		var user = await userManager.GetUserAsync(result.Principal)
			?? throw new InvalidOperationException("User not found.");

		// Build identity with requested claims
		var identity = new ClaimsIdentity(
			authenticationType: TokenValidationParameters.DefaultAuthenticationType,
			nameType: Claims.Name,
			roleType: Claims.Role);

		identity.SetClaim(Claims.Subject, await userManager.GetUserIdAsync(user))
				.SetClaim(Claims.Email, await userManager.GetEmailAsync(user))
				.SetClaim(Claims.Name, await userManager.GetUserNameAsync(user));

		// Add roles as claims
		var roles = await userManager.GetRolesAsync(user);
		foreach (var role in roles)
			identity.AddClaim(new Claim(Claims.Role, role));

		identity.SetScopes(request.GetScopes());
		identity.SetResources(await scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());
		identity.SetDestinations(GetDestinations);

		return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
	}

	// ─── Token Endpoint ───────────────────────────────────────────────────

	[HttpPost("~/connect/token")]
	public async Task<IActionResult> Exchange()
	{
		var request = HttpContext.GetOpenIddictServerRequest()
			?? throw new InvalidOperationException("OpenIddict request not found.");

		if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
		{
			var principal = (await HttpContext.AuthenticateAsync(
				OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;

			var user = await userManager.FindByIdAsync(principal!.GetClaim(Claims.Subject)!);
			if (user is null)
				return Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

			// Refresh user info in tokens
			var identity = new ClaimsIdentity(principal!.Claims,
				TokenValidationParameters.DefaultAuthenticationType,
				Claims.Name, Claims.Role);

			identity.SetClaim(Claims.Subject, await userManager.GetUserIdAsync(user))
					.SetClaim(Claims.Email, await userManager.GetEmailAsync(user))
					.SetClaim(Claims.Name, await userManager.GetUserNameAsync(user));

			var roles = await userManager.GetRolesAsync(user);
			foreach (var role in roles)
				identity.SetClaim(Claims.Role, role);

			identity.SetDestinations(GetDestinations);

			return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
		}

		if (request.IsPasswordGrantType())
		{
			var user = await userManager.FindByEmailAsync(request.Username!)
				?? await userManager.FindByNameAsync(request.Username!);

			if (user is null)
				return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
				{
					[OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
					[OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Invalid credentials."
				}), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

			// CheckPasswordSignInAsync handles lockout counter increments correctly
			var signInResult = await signInManager.CheckPasswordSignInAsync(
				user, request.Password!, lockoutOnFailure: true);

			if (!signInResult.Succeeded)
			{
				var description = signInResult.IsLockedOut
					? "Account is locked out."
					: "Invalid credentials.";

				return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
				{
					[OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
					[OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description
				}), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
			}

			var identity = new ClaimsIdentity(
				authenticationType: TokenValidationParameters.DefaultAuthenticationType,
				nameType: Claims.Name,
				roleType: Claims.Role);

			identity.SetClaim(Claims.Subject, await userManager.GetUserIdAsync(user))
					.SetClaim(Claims.Email, await userManager.GetEmailAsync(user))
					.SetClaim(Claims.Name, await userManager.GetUserNameAsync(user));

			var roles = await userManager.GetRolesAsync(user);
			foreach (var role in roles)
				identity.AddClaim(new Claim(Claims.Role, role));

			identity.SetScopes(request.GetScopes());
			identity.SetResources(await scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());
			identity.SetDestinations(GetDestinations);

			return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
		}

		if (request.IsClientCredentialsGrantType())
		{
			// OpenIddict has already validated the client_id and client_secret before
			// reaching here, so we can safely resolve the application.
			var application = await applicationManager.FindByClientIdAsync(request.ClientId!)
				?? throw new InvalidOperationException("The client application was not found.");

			var identity = new ClaimsIdentity(
				authenticationType: TokenValidationParameters.DefaultAuthenticationType,
				nameType: Claims.Name,
				roleType: Claims.Role);

			identity.SetClaim(Claims.Subject, await applicationManager.GetClientIdAsync(application));
			identity.SetClaim(Claims.Name, await applicationManager.GetDisplayNameAsync(application));

			identity.SetScopes(request.GetScopes());
			identity.SetResources(await scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());
			identity.SetDestinations(GetDestinations);

			return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
		}

		throw new InvalidOperationException($"Unsupported grant type: {request.GrantType}");
	}

	// ─── UserInfo Endpoint ────────────────────────────────────────────────

	[Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
	[HttpGet("~/connect/userinfo")]
	public async Task<IActionResult> UserInfo()
	{
		var user = await userManager.GetUserAsync(User);
		if (user is null)
			return Challenge(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

		var roles = await userManager.GetRolesAsync(user);

		return Ok(new Dictionary<string, object>
		{
			[Claims.Subject] = await userManager.GetUserIdAsync(user),
			[Claims.Email] = await userManager.GetEmailAsync(user) ?? string.Empty,
			[Claims.EmailVerified] = user.EmailConfirmed,
			[Claims.Name] = await userManager.GetUserNameAsync(user) ?? string.Empty,
			[Claims.Role] = roles,
		});
	}

	// ─── Logout Endpoint ──────────────────────────────────────────────────

	[HttpGet("~/connect/logout")]
	public async Task<IActionResult> Logout()
	{
		await signInManager.SignOutAsync();
		return SignOut(
			authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
			properties: new AuthenticationProperties { RedirectUri = "/" });
	}

	// ─── Helpers ──────────────────────────────────────────────────────────

	private static IEnumerable<string> GetDestinations(Claim claim)
	{
		return claim.Type switch
		{
			Claims.Name or Claims.Subject
				=> [Destinations.AccessToken, Destinations.IdentityToken],
			Claims.Email
				=> [Destinations.AccessToken, Destinations.IdentityToken],
			Claims.Role
				=> [Destinations.AccessToken, Destinations.IdentityToken],
			_ => [Destinations.AccessToken]
		};
	}
}
