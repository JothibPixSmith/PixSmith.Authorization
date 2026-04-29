using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Services;
using System.Security.Claims;

namespace AuthServer.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public sealed class AccountController(
	UserManager<IdentityUser<Guid>> userManager,
	SignInManager<IdentityUser<Guid>> signInManager,
	IUserService userService) : ControllerBase
{
	// ─── Register ─────────────────────────────────────────────────────────

	[HttpPost("register")]
	[ProducesResponseType(typeof(UserDto), 200)]
	[ProducesResponseType(typeof(ProblemDetails), 400)]
	public async Task<IActionResult> Register([FromBody] RegisterUserRequest request)
	{
		// Use domain service for business logic
		var result = await userService.RegisterAsync(request);
		if (!result.IsSuccess) return BadRequest(new { error = result.Error });

		// Create corresponding Identity user
		var identityUser = new IdentityUser<Guid>
		{
			Id = result.Value!.Id,
			UserName = request.Username,
			Email = request.Email,
		};

		var identityResult = await userManager.CreateAsync(identityUser, request.Password);
		if (!identityResult.Succeeded)
		{
			var errors = string.Join("; ", identityResult.Errors.Select(e => e.Description));
			return BadRequest(new { error = errors });
		}

		await userManager.AddToRoleAsync(identityUser, "User");
		return Ok(result.Value);
	}

	// ─── Login ────────────────────────────────────────────────────────────

	[HttpPost("login")]
	[ProducesResponseType(200)]
	[ProducesResponseType(typeof(ProblemDetails), 401)]
	public async Task<IActionResult> Login([FromBody] LoginRequest request)
	{
		var user = await userService.GetByEmailAsync(request.Email);


		var result = await signInManager.PasswordSignInAsync(
			user?.Value != null ? user.Value.Username : request.Email, request.Password,
			isPersistent: request.RememberMe,
			lockoutOnFailure: false);

		if (result.Succeeded) return Ok(new { message = "Login successful" });
		if (result.IsLockedOut) return StatusCode(423, new { error = "Account is locked out." });
		if (result.RequiresTwoFactor) return StatusCode(428, new { error = "2FA required.", redirectTo = "/2fa" });

		return Unauthorized(new { error = "Invalid email or password." });
	}

	// ─── Logout ───────────────────────────────────────────────────────────

	[HttpPost("logout")]
	[Authorize]
	public async Task<IActionResult> Logout()
	{
		await signInManager.SignOutAsync();
		return Ok();
	}

	// ─── External SSO Login ───────────────────────────────────────────────

	/// <summary>Initiates external provider login (Google, Microsoft, GitHub, etc.)</summary>
	[HttpGet("external-login")]
	public IActionResult ExternalLogin(string provider, string returnUrl = "/")
	{
		var redirectUrl = Url.Action(nameof(ExternalLoginCallback), values: new { returnUrl });
		var properties = signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
		return Challenge(properties, provider);
	}

	/// <summary>Handles the callback from the external provider.</summary>
	[HttpGet("external-login-callback")]
	public async Task<IActionResult> ExternalLoginCallback(string? returnUrl = null)
	{
		var info = await signInManager.GetExternalLoginInfoAsync();
		if (info is null) return Redirect($"/?error=external-login-failed");

		// Try to sign in with existing external login link
		var result = await signInManager.ExternalLoginSignInAsync(
			info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);

		if (result.Succeeded)
			return LocalRedirect(returnUrl ?? "/");

		// No existing link - find or create user in our domain
		var email = info.Principal.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
		var firstName = info.Principal.FindFirstValue(ClaimTypes.GivenName);
		var lastName = info.Principal.FindFirstValue(ClaimTypes.Surname);

		var userResult = await userService.FindOrCreateFromExternalLoginAsync(
			info.LoginProvider, info.ProviderKey, email, firstName, lastName);

		if (!userResult.IsSuccess)
			return Redirect($"/?error={Uri.EscapeDataString(userResult.Error!)}");

		// Link the external login to the Identity user
		var identityUser = await userManager.FindByEmailAsync(email);
		if (identityUser is not null)
		{
			await userManager.AddLoginAsync(identityUser, info);
			await signInManager.SignInAsync(identityUser, isPersistent: false);
		}

		return LocalRedirect(returnUrl ?? "/");
	}

	// ─── Profile ──────────────────────────────────────────────────────────

	[HttpGet("me")]
	[Authorize]
	[ProducesResponseType(typeof(UserDto), 200)]
	public async Task<IActionResult> Me()
	{
		var userId = userManager.GetUserId(User);
		if (userId is null) return Unauthorized();

		var result = await userService.GetByIdAsync(Guid.Parse(userId));
		return result.IsSuccess ? Ok(result.Value) : NotFound();
	}

	[HttpPut("me")]
	[Authorize]
	public async Task<IActionResult> UpdateProfile([FromBody] UpdateUserProfileRequest request)
	{
		var userId = userManager.GetUserId(User);
		if (userId is null) return Unauthorized();

		var result = await userService.UpdateProfileAsync(Guid.Parse(userId), request);
		return result.IsSuccess ? Ok(result.Value) : BadRequest(new { error = result.Error });
	}

	[HttpPost("change-password")]
	[Authorize]
	public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
	{
		var userId = userManager.GetUserId(User);
		if (userId is null) return Unauthorized();

		var result = await userService.ChangePasswordAsync(Guid.Parse(userId), request);
		return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
	}

	// ─── Password Reset ───────────────────────────────────────────────────

	[HttpPost("forgot-password")]
	public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
	{
		await userService.ForgotPasswordAsync(request);
		return Ok(new { message = "If an account with that email exists, a reset link has been sent." });
	}

	[HttpPost("reset-password")]
	public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
	{
		var result = await userService.ResetPasswordAsync(request);
		return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
	}
}
