using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Services;
using PixSmith.Authorization.Services.Interfaces;

namespace PixSmith.Authorization.API.Controllers;

[ApiController]
[Route("api/admin")]
[Authorize(Policy = "AdminAccess")]
public sealed class AdminController(
    IAdminService adminService,
    IUserService userService,
    IOAuthClientService clientService,
    UserManager<IdentityUser<Guid>> userManager) : ControllerBase
{
    // ─── Dashboard ────────────────────────────────────────────────────────────

    [HttpGet("dashboard")]
    [ProducesResponseType(typeof(DashboardStatsDto), 200)]
    public async Task<IActionResult> Dashboard()
    {
        var result = await adminService.GetDashboardStatsAsync();
        return result.IsSuccess ? Ok(result.Value) : StatusCode(500);
    }

    // ─── User Management ──────────────────────────────────────────────────────

    [HttpGet("users")]
    [ProducesResponseType(typeof(UserPagedResult), 200)]
    public async Task<IActionResult> GetUsers([FromQuery] int page = 1, [FromQuery] int pageSize = 20)
    {
        var result = await userService.GetAllAsync(page, pageSize);
        return result.IsSuccess ? Ok(result.Value) : StatusCode(500);
    }

    [HttpGet("users/{id:guid}")]
    [ProducesResponseType(typeof(UserDto), 200)]
    [ProducesResponseType(404)]
    public async Task<IActionResult> GetUser(Guid id)
    {
        var result = await userService.GetByIdAsync(id);
        return result.IsSuccess ? Ok(result.Value) : NotFound();
    }

    [HttpPost("users/{id:guid}/roles")]
    public async Task<IActionResult> AssignRole(Guid id, [FromBody] RoleRequest request)
    {
        var result = await adminService.AssignRoleAsync(id, request.RoleName);
        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }

    [HttpDelete("users/{id:guid}/roles/{roleName}")]
    public async Task<IActionResult> RemoveRole(Guid id, string roleName)
    {
        var result = await adminService.RemoveRoleAsync(id, roleName);
        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }

    [HttpPost("users/{id:guid}/activate")]
    public async Task<IActionResult> ActivateUser(Guid id)
    {
        var result = await userService.ActivateAsync(id);
        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }

    [HttpPost("users/{id:guid}/deactivate")]
    public async Task<IActionResult> DeactivateUser(Guid id)
    {
        var result = await userService.DeactivateAsync(id);
        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }

    [HttpPost("users/{id:guid}/unlock")]
    public async Task<IActionResult> UnlockUser(Guid id)
    {
        var result = await userService.UnlockAsync(id);
        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }

    [HttpDelete("users/{id:guid}")]
    public async Task<IActionResult> DeleteUser(Guid id)
    {
        var result = await adminService.DeleteUserAsync(id);
        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }

    // ─── Role Management ──────────────────────────────────────────────────────

    [HttpGet("roles")]
    [ProducesResponseType(typeof(IEnumerable<RoleDto>), 200)]
    public async Task<IActionResult> GetRoles()
    {
        var result = await adminService.GetRolesAsync();
        return result.IsSuccess ? Ok(result.Value) : StatusCode(500);
    }

    [HttpPost("roles")]
    [ProducesResponseType(typeof(RoleDto), 201)]
    [ProducesResponseType(typeof(ProblemDetails), 409)]
    public async Task<IActionResult> CreateRole([FromBody] CreateRoleRequest request)
    {
        var result = await adminService.CreateRoleAsync(request.Name);
        if (!result.IsSuccess)
        {
            return result.Error!.Contains("already exists")
                ? Conflict(new { error = result.Error })
                : BadRequest(new { error = result.Error });
        }

        return CreatedAtAction(nameof(GetRoles), result.Value);
    }

    [HttpDelete("roles/{roleName}")]
    [ProducesResponseType(204)]
    [ProducesResponseType(404)]
    [ProducesResponseType(typeof(ProblemDetails), 409)]
    public async Task<IActionResult> DeleteRole(string roleName)
    {
        var result = await adminService.DeleteRoleAsync(roleName);
        if (!result.IsSuccess)
        {
            return result.Error!.Contains("not found")
                ? NotFound()
                : result.Error.Contains("still assigned")
                    ? Conflict(new { error = result.Error })
                    : BadRequest(new { error = result.Error });
        }

        return NoContent();
    }

    // ─── OAuth Client Management ──────────────────────────────────────────────

    [HttpGet("clients")]
    [ProducesResponseType(typeof(IEnumerable<OAuthClientDto>), 200)]
    public async Task<IActionResult> GetClients()
    {
        var result = await clientService.GetAllAsync();
        return result.IsSuccess ? Ok(result.Value) : StatusCode(500);
    }

    [HttpGet("clients/{id:guid}")]
    [ProducesResponseType(typeof(OAuthClientDto), 200)]
    public async Task<IActionResult> GetClient(Guid id)
    {
        var result = await clientService.GetByIdAsync(id);
        return result.IsSuccess ? Ok(result.Value) : NotFound();
    }

    [HttpPost("clients")]
    [ProducesResponseType(typeof(CreateOAuthClientResponse), 201)]
    public async Task<IActionResult> CreateClient([FromBody] CreateOAuthClientRequest request)
    {
        var userId = userManager.GetUserId(User);
        var result = await clientService.CreateAsync(request, Guid.Parse(userId!));
        if (!result.IsSuccess) return BadRequest(new { error = result.Error });

        return CreatedAtAction(nameof(GetClient), new { id = result.Value!.Id }, result.Value);
    }

    [HttpPut("clients/{id:guid}")]
    public async Task<IActionResult> UpdateClient(Guid id, [FromBody] UpdateOAuthClientRequest request)
    {
        var result = await clientService.UpdateAsync(id, request);
        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }

    [HttpPost("clients/{id:guid}/redirect-uris")]
    public async Task<IActionResult> AddRedirectUri(Guid id, [FromBody] UriRequest request)
    {
        var result = await clientService.AddRedirectUriAsync(id, request.Uri);
        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }

    [HttpDelete("clients/{id:guid}/redirect-uris")]
    public async Task<IActionResult> RemoveRedirectUri(Guid id, [FromBody] UriRequest request)
    {
        var result = await clientService.RemoveRedirectUriAsync(id, request.Uri);
        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }

    [HttpPost("clients/{id:guid}/activate")]
    public async Task<IActionResult> ActivateClient(Guid id)
    {
        var result = await clientService.ActivateAsync(id);
        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }

    [HttpPost("clients/{id:guid}/deactivate")]
    public async Task<IActionResult> DeactivateClient(Guid id)
    {
        var result = await clientService.DeactivateAsync(id);
        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }

    [HttpDelete("clients/{id:guid}")]
    public async Task<IActionResult> DeleteClient(Guid id)
    {
        var result = await clientService.DeleteAsync(id);
        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }
}
