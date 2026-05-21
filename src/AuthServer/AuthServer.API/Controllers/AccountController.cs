using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Services;
using PixSmith.Authorization.Services.Interfaces;
using System.Net.Http.Json;
using System.Text.Json;

namespace AuthServer.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public sealed class AccountController(
    IAccountService accountService,
    IUserService userService,
    SignInManager<IdentityUser<Guid>> signInManager,
    UserManager<IdentityUser<Guid>> userManager,
    IHttpClientFactory httpClientFactory) : ControllerBase
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

    // ─── Login ────────────────────────────────────────────────────────────────

    [HttpPost("login")]
    [AllowAnonymous]
    [ProducesResponseType(200)]
    [ProducesResponseType(401)]
    [ProducesResponseType(423)]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var identityUser = await userManager.FindByEmailAsync(request.Email);
        if (identityUser is null)
            return Unauthorized(new { error = "Invalid email or password." });

        var signInResult = await signInManager.CheckPasswordSignInAsync(
            identityUser, request.Password, lockoutOnFailure: true);

        if (signInResult.IsLockedOut)
            return StatusCode(423, new { error = "Account is locked out. Please try again later." });

        if (!signInResult.Succeeded)
            return Unauthorized(new { error = "Invalid email or password." });

        // Issue an encrypted access token via OpenIddict password grant (loopback)
        var tokenEndpoint = $"{Request.Scheme}://{Request.Host}/connect/token";
        var http = httpClientFactory.CreateClient("Self");

        using var tokenResponse = await http.PostAsync(tokenEndpoint,
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["username"]   = identityUser.UserName!,
                ["password"]   = request.Password,
                ["scope"]      = "openid profile email roles offline_access api",
                ["client_id"]  = "blazor-client",
            }));

        if (!tokenResponse.IsSuccessStatusCode)
            return StatusCode(500, new { error = "Token issuance failed." });

        var tokenData = await tokenResponse.Content.ReadFromJsonAsync<JsonElement>();
        var userResult = await userService.GetByIdAsync(identityUser.Id);

        return Ok(new
        {
            access_token  = tokenData.GetProperty("access_token").GetString(),
            token_type    = "Bearer",
            expires_in    = tokenData.TryGetProperty("expires_in", out var expProp) ? expProp.GetInt32() : 3600,
            refresh_token = tokenData.TryGetProperty("refresh_token", out var rfProp) ? rfProp.GetString() : null,
            user          = userResult.IsSuccess ? userResult.Value : null,
        });
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
