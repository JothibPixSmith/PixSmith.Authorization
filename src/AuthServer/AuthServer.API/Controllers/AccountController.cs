using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Services;
using PixSmith.Authorization.Services.Interfaces;
using System.Security.Claims;

namespace AuthServer.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public sealed class AccountController(
    IAccountService accountService,
    IUserService userService,
    SignInManager<IdentityUser<Guid>> signInManager,
    UserManager<IdentityUser<Guid>> userManager) : ControllerBase
{
    // ─── Register ─────────────────────────────────────────────────────────────

    [HttpPost("register")]
    [ProducesResponseType(typeof(UserDto), 200)]
    [ProducesResponseType(typeof(ProblemDetails), 400)]
    public async Task<IActionResult> Register([FromBody] RegisterUserRequest request)
    {
        var result = await accountService.RegisterAsync(request);
        return result.IsSuccess ? Ok(result.Value) : BadRequest(new { error = result.Error });
    }

    // ─── External SSO ─────────────────────────────────────────────────────────

    [HttpGet("external-login")]
    public IActionResult ExternalLogin(string provider, string returnUrl = "/")
    {
        var redirectUrl = Url.Action(nameof(ExternalLoginCallback), values: new { returnUrl });
        var properties  = signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
        return Challenge(properties, provider);
    }

    [HttpGet("external-login-callback")]
    public async Task<IActionResult> ExternalLoginCallback(string? returnUrl = null)
    {
        var info = await signInManager.GetExternalLoginInfoAsync();
        if (info is null) return Redirect($"/?error=external-login-failed");

        // Happy path: existing linked account signs straight in
        var signInResult = await signInManager.ExternalLoginSignInAsync(
            info.LoginProvider, info.ProviderKey,
            isPersistent: false, bypassTwoFactor: true);

        if (signInResult.Succeeded)
            return LocalRedirect(returnUrl ?? "/");

        // New account or new provider link: create/link domain + Identity
        var email     = info.Principal.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
        var firstName = info.Principal.FindFirstValue(ClaimTypes.GivenName);
        var lastName  = info.Principal.FindFirstValue(ClaimTypes.Surname);

        var linkResult = await accountService.LinkExternalLoginAsync(
            info.LoginProvider, info.ProviderKey, info, email, firstName, lastName);

        if (!linkResult.IsSuccess)
            return Redirect($"/?error={Uri.EscapeDataString(linkResult.Error!)}");

        // Sign the user in via the newly linked Identity login
        var identityUser = await userManager.FindByEmailAsync(email);
        if (identityUser is not null)
            await signInManager.SignInAsync(identityUser, isPersistent: false);

        return LocalRedirect(returnUrl ?? "/");
    }

    // ─── Profile ──────────────────────────────────────────────────────────────

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

    // ─── Password Reset ───────────────────────────────────────────────────────

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
