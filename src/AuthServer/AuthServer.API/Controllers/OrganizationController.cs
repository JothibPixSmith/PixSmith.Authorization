using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Validation.AspNetCore;
using PixSmith.Authorization.API.Security;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Services.Interfaces;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PixSmith.Authorization.API.Controllers;

/// <summary>
/// Self-service company administration: a company's own <c>OrgAdmin</c> manages that company's
/// members without needing platform rights.
///
/// <para>
/// Deliberately a separate surface from <c>AdminController</c>, which requires the platform
/// <c>Admin</c> role and <c>admin</c> scope at the class level — an <c>OrgAdmin</c> would be
/// rejected there before any per-action check could run. The two are genuinely different
/// authorities: this one is scoped to a single tenancy, established from the caller's own token.
/// </para>
/// </summary>
[ApiController]
[Route("api/organizations")]
[Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
public sealed class OrganizationController(
    ITenantAccessService tenantAccessService) : ControllerBase
{
    /// <summary>
    /// The companies the caller belongs to, from their own token. Needs no org-scoped check:
    /// it only ever reports the caller's own memberships.
    /// </summary>
    [HttpGet("mine")]
    [ProducesResponseType(typeof(IEnumerable<UserMembershipDto>), 200)]
    public async Task<IActionResult> GetMyOrganizations(CancellationToken ct)
    {
        if (!Guid.TryParse(User.FindFirst(Claims.Subject)?.Value, out var userId))
            return Forbid();

        var result = await tenantAccessService.GetMembershipsForUserAsync(userId, ct);
        return result.IsSuccess ? Ok(result.Value) : StatusCode(500);
    }

    [HttpGet("{tenantId:guid}/members")]
    [AllowOrgAdmin]
    [ProducesResponseType(typeof(IEnumerable<TenantMemberDto>), 200)]
    public async Task<IActionResult> GetMembers(Guid tenantId, CancellationToken ct)
    {
        var result = await tenantAccessService.GetMembersAsync(tenantId, ct);
        return result.IsSuccess ? Ok(result.Value) : NotFound(new { error = result.Error });
    }

    /// <summary>Invites an existing account into this company by email address.</summary>
    [HttpPost("{tenantId:guid}/members")]
    [AllowOrgAdmin]
    [ProducesResponseType(typeof(TenantMemberDto), 201)]
    [ProducesResponseType(typeof(ProblemDetails), 400)]
    public async Task<IActionResult> InviteMember(
        Guid tenantId, [FromBody] InviteMemberRequest request, CancellationToken ct)
    {
        var result = await tenantAccessService.InviteMemberByEmailAsync(tenantId, request, ct);
        if (!result.IsSuccess) return BadRequest(new { error = result.Error });

        return CreatedAtAction(nameof(GetMembers), new { tenantId }, result.Value);
    }

    [HttpPut("{tenantId:guid}/members/{userId:guid}")]
    [AllowOrgAdmin]
    public async Task<IActionResult> UpdateMember(
        Guid tenantId, Guid userId, [FromBody] UpdateTenantMemberRequest request, CancellationToken ct)
    {
        var result = await tenantAccessService.UpdateMemberAsync(tenantId, userId, request, ct);
        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }

    [HttpDelete("{tenantId:guid}/members/{userId:guid}")]
    [AllowOrgAdmin]
    public async Task<IActionResult> RemoveMember(Guid tenantId, Guid userId, CancellationToken ct)
    {
        // An OrgAdmin removing themselves would leave the company unmanageable, so it is
        // refused here rather than discovered afterwards.
        if (Guid.TryParse(User.FindFirst(Claims.Subject)?.Value, out var caller) && caller == userId)
            return BadRequest(new { error = "You cannot remove your own membership." });

        var result = await tenantAccessService.RemoveMemberAsync(tenantId, userId, ct);
        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }

    [HttpPut("{tenantId:guid}/members/{userId:guid}/applications/{clientId}")]
    [AllowOrgAdmin]
    public async Task<IActionResult> SetMemberApplicationAccess(
        Guid tenantId, Guid userId, string clientId,
        [FromBody] SetMemberApplicationAccessRequest request, CancellationToken ct)
    {
        var result = await tenantAccessService
            .SetMemberApplicationAccessAsync(tenantId, userId, clientId, request, ct);

        return result.IsSuccess ? Ok() : BadRequest(new { error = result.Error });
    }
}
