using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PixSmith.Authorization.API.Security;
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
    ITenantService tenantService,
    ITenantAccessService tenantAccessService,
    IOidcAppService oidcAppService,
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

    [HttpPut("users/{id:guid}")]
    [ProducesResponseType(typeof(UserDto), 200)]
    [ProducesResponseType(404)]
    public async Task<IActionResult> UpdateUser(Guid id, [FromBody] AdminUpdateUserRequest request)
    {
        var result = await adminService.UpdateUserAsync(id, request);
        return result.IsSuccess ? Ok(result.Value) : BadRequest(new { error = result.Error });
    }

    [HttpPost("users/{id:guid}/reset-password")]
    public async Task<IActionResult> ResetPassword(Guid id, [FromBody] AdminResetPasswordRequest request)
    {
        var result = await adminService.ResetPasswordAsync(id, request.NewPassword);
        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }

    [HttpGet("users/{id:guid}/claims")]
    [ProducesResponseType(typeof(IReadOnlyList<ClaimDto>), 200)]
    public async Task<IActionResult> GetClaims(Guid id)
    {
        var result = await adminService.GetClaimsAsync(id);
        return result.IsSuccess ? Ok(result.Value) : NotFound();
    }

    [HttpPost("users/{id:guid}/claims")]
    public async Task<IActionResult> AddClaim(Guid id, [FromBody] AddClaimRequest request)
    {
        var result = await adminService.AddClaimAsync(id, request.Type, request.Value);
        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }

    [HttpDelete("users/{id:guid}/claims")]
    public async Task<IActionResult> RemoveClaim(Guid id, [FromQuery] string type, [FromQuery] string value)
    {
        var result = await adminService.RemoveClaimAsync(id, type, value);
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

    // ─── Tenant Management ────────────────────────────────────────────────────

    [HttpGet("tenants")]
    [ProducesResponseType(typeof(IEnumerable<TenantDto>), 200)]
    public async Task<IActionResult> GetTenants()
    {
        var result = await tenantService.GetAllAsync();
        return result.IsSuccess ? Ok(result.Value) : StatusCode(500);
    }

    [HttpGet("tenants/{id:guid}")]
    [ProducesResponseType(typeof(TenantDto), 200)]
    [ProducesResponseType(404)]
    public async Task<IActionResult> GetTenant(Guid id)
    {
        var result = await tenantService.GetByIdAsync(id);
        return result.IsSuccess ? Ok(result.Value) : NotFound();
    }

    // Every mutating tenant operation below is gated on an offline signature quorum plus an
    // interactive human administrator. Read operations are not — listing tenants is not a
    // way to gain control of the registry, and gating it would make the control unusable.
    //
    // Delete and deactivate are gated alongside create deliberately: an attacker who can
    // delete a tenancy and recreate it under their own control has taken over the registry
    // just as effectively as one who can create at will.

    [HttpPost("tenants")]
    [RequireProvisioningSignature]
    [ProducesResponseType(typeof(TenantDto), 201)]
    [ProducesResponseType(typeof(ProblemDetails), 403)]
    public async Task<IActionResult> CreateTenant([FromBody] CreateTenantRequest request)
    {
        var result = await tenantService.CreateAsync(request);
        if (!result.IsSuccess) return BadRequest(new { error = result.Error });
        return CreatedAtAction(nameof(GetTenant), new { id = result.Value!.Id }, result.Value);
    }

    [HttpPut("tenants/{id:guid}")]
    [RequireProvisioningSignature]
    public async Task<IActionResult> UpdateTenant(Guid id, [FromBody] UpdateTenantRequest request)
    {
        var result = await tenantService.UpdateAsync(id, request);
        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }

    [HttpPost("tenants/{id:guid}/activate")]
    [RequireProvisioningSignature]
    public async Task<IActionResult> ActivateTenant(Guid id)
    {
        var result = await tenantService.ActivateAsync(id);
        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }

    [HttpPost("tenants/{id:guid}/deactivate")]
    [RequireProvisioningSignature]
    public async Task<IActionResult> DeactivateTenant(Guid id)
    {
        var result = await tenantService.DeactivateAsync(id);
        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }

    [HttpDelete("tenants/{id:guid}")]
    [RequireProvisioningSignature]
    public async Task<IActionResult> DeleteTenant(Guid id)
    {
        var result = await tenantService.DeleteAsync(id);
        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }


    // ─── Tenant Membership & Subscriptions ────────────────────────────────────
    //
    // Not gated by [RequireProvisioningSignature]. That control guards the tenant
    // *registry* — bringing a tenancy into existence. Adding a member to a company that
    // already exists, or subscribing it to an application, is routine administration
    // within an established tenancy, and requiring two offline signatures for every
    // staff change would make the control something people route around.

    [HttpGet("tenants/{tenantId:guid}/members")]
    [ProducesResponseType(typeof(IEnumerable<TenantMemberDto>), 200)]
    public async Task<IActionResult> GetTenantMembers(Guid tenantId, CancellationToken ct)
    {
        var result = await tenantAccessService.GetMembersAsync(tenantId, ct);
        return result.IsSuccess ? Ok(result.Value) : NotFound(new { error = result.Error });
    }

    [HttpPost("tenants/{tenantId:guid}/members")]
    [ProducesResponseType(typeof(TenantMemberDto), 201)]
    public async Task<IActionResult> AddTenantMember(
        Guid tenantId, [FromBody] AddTenantMemberRequest request, CancellationToken ct)
    {
        var result = await tenantAccessService.AddMemberAsync(tenantId, request, ct);
        if (!result.IsSuccess) return BadRequest(new { error = result.Error });

        return CreatedAtAction(nameof(GetTenantMembers), new { tenantId }, result.Value);
    }

    [HttpPut("tenants/{tenantId:guid}/members/{userId:guid}")]
    public async Task<IActionResult> UpdateTenantMember(
        Guid tenantId, Guid userId, [FromBody] UpdateTenantMemberRequest request, CancellationToken ct)
    {
        var result = await tenantAccessService.UpdateMemberAsync(tenantId, userId, request, ct);
        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }

    [HttpDelete("tenants/{tenantId:guid}/members/{userId:guid}")]
    public async Task<IActionResult> RemoveTenantMember(Guid tenantId, Guid userId, CancellationToken ct)
    {
        var result = await tenantAccessService.RemoveMemberAsync(tenantId, userId, ct);
        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }

    /// <summary>Every company a user belongs to — the data behind a company picker.</summary>
    [HttpGet("users/{userId:guid}/memberships")]
    [ProducesResponseType(typeof(IEnumerable<UserMembershipDto>), 200)]
    public async Task<IActionResult> GetUserMemberships(Guid userId, CancellationToken ct)
    {
        var result = await tenantAccessService.GetMembershipsForUserAsync(userId, ct);
        return result.IsSuccess ? Ok(result.Value) : StatusCode(500);
    }

    [HttpGet("tenants/{tenantId:guid}/applications")]
    [ProducesResponseType(typeof(IEnumerable<TenantApplicationDto>), 200)]
    public async Task<IActionResult> GetTenantApplications(Guid tenantId, CancellationToken ct)
    {
        var result = await tenantAccessService.GetApplicationsAsync(tenantId, ct);
        return result.IsSuccess ? Ok(result.Value) : NotFound(new { error = result.Error });
    }

    [HttpPost("tenants/{tenantId:guid}/applications")]
    [ProducesResponseType(typeof(TenantApplicationDto), 201)]
    public async Task<IActionResult> AddTenantApplication(
        Guid tenantId, [FromBody] AddTenantApplicationRequest request, CancellationToken ct)
    {
        var result = await tenantAccessService.AddApplicationAsync(tenantId, request, ct);
        if (!result.IsSuccess) return BadRequest(new { error = result.Error });

        return CreatedAtAction(nameof(GetTenantApplications), new { tenantId }, result.Value);
    }

    [HttpPut("tenants/{tenantId:guid}/applications/{clientId}")]
    public async Task<IActionResult> UpdateTenantApplication(
        Guid tenantId, string clientId, [FromBody] UpdateTenantApplicationRequest request, CancellationToken ct)
    {
        var result = await tenantAccessService.UpdateApplicationAsync(tenantId, clientId, request, ct);
        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }

    [HttpDelete("tenants/{tenantId:guid}/applications/{clientId}")]
    public async Task<IActionResult> RemoveTenantApplication(
        Guid tenantId, string clientId, CancellationToken ct)
    {
        var result = await tenantAccessService.RemoveApplicationAsync(tenantId, clientId, ct);
        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }

    // ─── OpenIddict Application Management ───────────────────────────────────

    [HttpGet("oidc-apps")]
    [ProducesResponseType(typeof(IReadOnlyList<OidcAppDto>), 200)]
    public async Task<IActionResult> GetOidcApps(CancellationToken ct)
    {
        var result = await oidcAppService.GetAllAsync(ct);
        return result.IsSuccess ? Ok(result.Value) : StatusCode(500, new { error = result.Error });
    }

    [HttpGet("oidc-apps/{clientId}")]
    [ProducesResponseType(typeof(OidcAppDto), 200)]
    [ProducesResponseType(404)]
    public async Task<IActionResult> GetOidcApp(string clientId, CancellationToken ct)
    {
        var result = await oidcAppService.GetByClientIdAsync(clientId, ct);
        return result.IsSuccess ? Ok(result.Value) : NotFound();
    }

    [HttpPost("oidc-apps")]
    [ProducesResponseType(typeof(OidcAppDto), 201)]
    public async Task<IActionResult> CreateOidcApp([FromBody] CreateOidcAppRequest request, CancellationToken ct)
    {
        var result = await oidcAppService.CreateAsync(request, ct);
        if (!result.IsSuccess) return BadRequest(new { error = result.Error });
        return CreatedAtAction(nameof(GetOidcApp), new { clientId = result.Value!.ClientId }, result.Value);
    }

    [HttpPut("oidc-apps/{clientId}")]
    public async Task<IActionResult> UpdateOidcApp(string clientId, [FromBody] UpdateOidcAppRequest request, CancellationToken ct)
    {
        var result = await oidcAppService.UpdateAsync(clientId, request, ct);
        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }

    [HttpDelete("oidc-apps/{clientId}")]
    public async Task<IActionResult> DeleteOidcApp(string clientId, CancellationToken ct)
    {
        var result = await oidcAppService.DeleteAsync(clientId, ct);
        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }

    /// <summary>
    /// Rotates a confidential application's client secret and returns the new value.
    ///
    /// <para>
    /// Separate from the update endpoint deliberately: rotation invalidates the credentials
    /// every deployment of that client is using, and that should never be a side effect of
    /// editing a redirect URI.
    /// </para>
    /// </summary>
    [HttpPost("oidc-apps/{clientId}/rotate-secret")]
    [ProducesResponseType(typeof(RotateClientSecretResponse), 200)]
    [ProducesResponseType(typeof(ProblemDetails), 400)]
    public async Task<IActionResult> RotateOidcAppSecret(
        string clientId, [FromBody] RotateClientSecretRequest? request, CancellationToken ct)
    {
        // The body is optional: no secret supplied means "generate one".
        var result = await oidcAppService.RotateSecretAsync(
            clientId, request ?? new RotateClientSecretRequest(null), ct);

        return result.IsSuccess ? Ok(result.Value) : BadRequest(new { error = result.Error });
    }
}
