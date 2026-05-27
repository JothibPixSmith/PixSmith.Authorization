using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Services;
using PixSmith.Authorization.Services.Interfaces;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PixSmith.Authorization.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public sealed class AccountController(
    IAccountService accountService,
    IUserService userService) : ControllerBase
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

    // ─── Profile ──────────────────────────────────────────────────────────────

    [HttpGet("me")]
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    [ProducesResponseType(typeof(UserDto), 200)]
    public async Task<IActionResult> Me()
    {
        var userId = User.GetClaim(Claims.Subject);
        if (userId is null) return Unauthorized();

        var result = await userService.GetByIdAsync(Guid.Parse(userId));
        return result.IsSuccess ? Ok(result.Value) : NotFound();
    }

    [HttpPut("me")]
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    public async Task<IActionResult> UpdateProfile([FromBody] UpdateUserProfileRequest request)
    {
        var userId = User.GetClaim(Claims.Subject);
        if (userId is null) return Unauthorized();

        var result = await userService.UpdateProfileAsync(Guid.Parse(userId), request);
        return result.IsSuccess ? Ok(result.Value) : BadRequest(new { error = result.Error });
    }

    [HttpPost("change-password")]
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
    {
        var userId = User.GetClaim(Claims.Subject);
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
