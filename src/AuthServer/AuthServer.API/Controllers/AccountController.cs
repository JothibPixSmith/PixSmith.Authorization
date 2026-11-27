using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Services;
using PixSmith.Authorization.Services.Interfaces;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PixSmith.Authorization.API.Controllers;

/// <summary>
/// The account API the admin UI calls. Three actions here act on the caller's own account and
/// take the <c>ApiAccess</c> policy — a valid token is not enough, it must have been granted the
/// <c>api</c> scope. Registration, password reset and email confirmation are deliberately
/// anonymous: they are reached before anyone has a token.
/// </summary>
[ApiController]
[Route("api/[controller]")]
public sealed class AccountController(
    IAccountService accountService,
    IUserService userService) : ControllerBase
{
    // ─── Register ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Registers a user. Returns the same body and status whether or not the address was
    /// already taken, so the endpoint cannot be used to enumerate accounts; a 400 only ever
    /// reflects input the caller can fix, such as a password that fails the policy.
    /// </summary>
    [HttpPost("register")]
    [EnableRateLimiting(Security.RateLimiting.AuthPolicy)]
    [ProducesResponseType(typeof(RegistrationAcceptedDto), 200)]
    [ProducesResponseType(typeof(ProblemDetails), 400)]
    public async Task<IActionResult> Register([FromBody] RegisterUserRequest request)
    {
        var result = await accountService.RegisterAsync(request);
        return result.IsSuccess ? Ok(result.Value) : BadRequest(new { error = result.Error });
    }

    // ─── Profile ──────────────────────────────────────────────────────────────

    [HttpGet("me")]
    [Authorize(Policy = "ApiAccess")]
    [ProducesResponseType(typeof(UserDto), 200)]
    public async Task<IActionResult> Me()
    {
        if (!Guid.TryParse(User.GetClaim(Claims.Subject), out var userId))
            return Forbid();   // a client-credentials token has a client id as its subject

        var result = await userService.GetByIdAsync(userId);
        return result.IsSuccess ? Ok(result.Value) : NotFound();
    }

    [HttpPut("me")]
    [Authorize(Policy = "ApiAccess")]
    public async Task<IActionResult> UpdateProfile([FromBody] UpdateUserProfileRequest request)
    {
        if (!Guid.TryParse(User.GetClaim(Claims.Subject), out var userId))
            return Forbid();

        var result = await userService.UpdateProfileAsync(userId, request);
        return result.IsSuccess ? Ok(result.Value) : BadRequest(new { error = result.Error });
    }

    [HttpPost("change-password")]
    [Authorize(Policy = "ApiAccess")]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
    {
        if (!Guid.TryParse(User.GetClaim(Claims.Subject), out var userId))
            return Forbid();

        var result = await userService.ChangePasswordAsync(userId, request);
        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }

    // ─── Password Reset ───────────────────────────────────────────────────────

    [HttpPost("forgot-password")]
    [EnableRateLimiting(Security.RateLimiting.AuthPolicy)]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
    {
        await userService.ForgotPasswordAsync(request);
        return Ok(new { message = "If an account with that email exists, a reset link has been sent." });
    }

    [HttpPost("reset-password")]
    [EnableRateLimiting(Security.RateLimiting.AuthPolicy)]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        var result = await userService.ResetPasswordAsync(request);
        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }

    // ─── Email Confirmation ───────────────────────────────────────────────────

    [HttpGet("confirm-email")]
    public async Task<IActionResult> ConfirmEmail([FromQuery] string email, [FromQuery] string token)
    {
        var result = await userService.ConfirmEmailAsync(email, token);
        return result.IsSuccess ? Ok(new { message = "Email confirmed." }) : BadRequest(new { error = result.Error });
    }
}
