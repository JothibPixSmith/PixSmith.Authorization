using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Services;
using PixSmith.Authorization.Services.Interfaces;

namespace AuthServer.API.Controllers;

/// <summary>
/// Admin-only endpoints for user management, client management, and dashboard stats.
/// Requires the "Admin" role.
/// </summary>
[ApiController]
[Route("api/admin")]
[Authorize(Roles = "Admin")]
public sealed class AdminController : ControllerBase
{
	private readonly IUserService userService;
	private readonly IOAuthClientService clientService;
	private readonly UserManager<IdentityUser<Guid>> userManager;
	private readonly RoleManager<IdentityRole<Guid>> roleManager;

	public AdminController(
		IUserService userService,
		IOAuthClientService clientService,
		UserManager<IdentityUser<Guid>> userManager,
		RoleManager<IdentityRole<Guid>> roleManager)
	{
		this.userService = userService;
		this.clientService = clientService;
		this.userManager = userManager;
		this.roleManager = roleManager;
	}

	// ─── Dashboard ────────────────────────────────────────────────────────

	[HttpGet("dashboard")]
	[ProducesResponseType(typeof(DashboardStatsDto), 200)]
	public async Task<IActionResult> Dashboard()
	{
		var usersResult = await userService.GetAllAsync(1, 1000);
		if (!usersResult.IsSuccess) return StatusCode(500);

		var all = usersResult.Value!.Items;
		var activeUsers = all.Count(u => u.IsActive && !u.IsLocked);
		var lockedUsers = all.Count(u => u.IsLocked);

		var clientsResult = await this.clientService.GetAllAsync();
		var clients = clientsResult.Value?.ToList() ?? [];

		var recentLogins = all
			.Where(u => u.LastLoginAt.HasValue)
			.OrderByDescending(u => u.LastLoginAt)
			.Take(10)
			.Select(u => new RecentLoginDto(u.Username, u.Email, u.LastLoginAt!.Value))
			.ToList();

		var stats = new DashboardStatsDto(
			TotalUsers: all.Count,
			ActiveUsers: activeUsers,
			LockedUsers: lockedUsers,
			TotalClients: clients.Count,
			ActiveClients: clients.Count(c => c.IsActive),
			RecentLogins: recentLogins);

		return Ok(stats);
	}

	// ─── User Management ──────────────────────────────────────────────────

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
		var result = await userService.AssignRoleAsync(id, request.RoleName);
		if (!result.IsSuccess) return BadRequest(new { error = result.Error });

		// Also assign via Identity
		var user = await userManager.FindByIdAsync(id.ToString());
		if (user is not null)
		{
			await EnsureRoleExistsAsync(request.RoleName);
			await userManager.AddToRoleAsync(user, request.RoleName);
		}

		return Ok();
	}

	[HttpDelete("users/{id:guid}/roles/{roleName}")]
	public async Task<IActionResult> RemoveRole(Guid id, string roleName)
	{
		var result = await userService.RemoveRoleAsync(id, roleName);
		if (!result.IsSuccess) return BadRequest(new { error = result.Error });

		var user = await userManager.FindByIdAsync(id.ToString());
		if (user is not null)
			await userManager.RemoveFromRoleAsync(user, roleName);

		return Ok();
	}

	[HttpPost("users/{id:guid}/deactivate")]
	public async Task<IActionResult> Deactivate(Guid id)
	{
		var result = await userService.DeactivateAsync(id);
		return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
	}

	[HttpPost("users/{id:guid}/activate")]
	public async Task<IActionResult> Activate(Guid id)
	{
		var result = await userService.ActivateAsync(id);
		return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
	}

	[HttpPost("users/{id:guid}/unlock")]
	public async Task<IActionResult> Unlock(Guid id)
	{
		var result = await userService.UnlockAsync(id);
		return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
	}

	[HttpDelete("users/{id:guid}")]
	public async Task<IActionResult> DeleteUser(Guid id)
	{
		var user = await userManager.FindByIdAsync(id.ToString());
		if (user is null) return NotFound();

		var result = await userManager.DeleteAsync(user);
		return result.Succeeded ? Ok() : BadRequest(result.Errors);
	}

	// ─── OAuth Client Management ──────────────────────────────────────────

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

	[HttpDelete("clients/{id:guid}")]
	public async Task<IActionResult> DeleteClient(Guid id)
	{
		var result = await clientService.DeleteAsync(id);
		return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
	}

	// ─── Helpers ──────────────────────────────────────────────────────────

	private async Task EnsureRoleExistsAsync(string roleName)
	{
		if (!await roleManager.RoleExistsAsync(roleName))
			await roleManager.CreateAsync(new IdentityRole<Guid>(roleName));
	}
}

public sealed record RoleRequest(string RoleName);
public sealed record UriRequest(string Uri);
