using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using OpenIddict.Abstractions;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Services;
using PixSmith.Authorization.Services.Interfaces;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PixSmith.Authorization.API.Security;

/// <summary>
/// Requires that the action be authorized by a quorum of offline provisioning signatures
/// <b>and</b> submitted by an authenticated human administrator.
///
/// <para>
/// The two halves are independent on purpose. The signature quorum proves that people holding
/// physically distributed key material approved this exact request. The human-principal check
/// proves an application did not initiate it at all — a machine-to-machine token can never
/// satisfy it, no matter which scopes it was granted.
/// </para>
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class)]
public sealed class RequireProvisioningSignatureAttribute : Attribute, IFilterFactory
{
    public bool IsReusable => false;

    public IFilterMetadata CreateInstance(IServiceProvider serviceProvider) =>
        ActivatorUtilities.CreateInstance<ProvisioningSignatureFilter>(serviceProvider);
}

public sealed class ProvisioningSignatureFilter(
    IProvisioningAuthorizer authorizer,
    UserManager<IdentityUser<Guid>> userManager,
    ApplicationDbContext db,
    ILogger<ProvisioningSignatureFilter> logger) : IAsyncAuthorizationFilter
{
    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        var http = context.HttpContext;
        var ct = http.RequestAborted;

        // ── Half one: this must be a human ────────────────────────────────────────

        var operatorId = await ResolveHumanOperatorAsync(context);
        if (operatorId is null)
        {
            logger.LogWarning(
                "Tenant provisioning refused for {Method} {Path}: caller is not an authenticated " +
                "human administrator.", http.Request.Method, http.Request.Path);

            await AuditAsync(null, http, "tenant.provision.denied",
                "Caller is not an authenticated human administrator.", ct);

            context.Result = Problem(context, StatusCodes.Status403Forbidden,
                "Human authorization required",
                "Tenant provisioning cannot be performed by an application identity. It requires an " +
                "interactive administrator session plus offline provisioning signatures.");
            return;
        }

        // ── Half two: the signature quorum ────────────────────────────────────────

        var body = await ReadBodyAsync(http, ct);

        var attempt = new ProvisioningAttempt(
            Method:             http.Request.Method,
            Path:               http.Request.Path.Value ?? string.Empty,
            Nonce:              http.Request.Headers[ProvisioningSignature.NonceHeader].FirstOrDefault(),
            Timestamp:          http.Request.Headers[ProvisioningSignature.TimestampHeader].FirstOrDefault(),
            SignatureHeaders:   [.. http.Request.Headers[ProvisioningSignature.SignatureHeader]
                                      .Where(h => !string.IsNullOrWhiteSpace(h))
                                      .Select(h => h!)],
            Body:               body,
            SubmittedByUserId:  operatorId);

        var outcome = await authorizer.AuthorizeAsync(attempt, ct);

        if (!outcome.Authorized)
        {
            await AuditAsync(operatorId, http, "tenant.provision.denied", outcome.Reason, ct);

            context.Result = Problem(context, StatusCodes.Status403Forbidden,
                "Provisioning signature required", outcome.Reason);
            return;
        }

        await AuditAsync(operatorId, http, "tenant.provision.authorized",
            $"Signed by: {string.Join(", ", outcome.SignedBy)}", ct);

        logger.LogInformation(
            "Tenant provisioning authorized for {Method} {Path} by operator {UserId}, signed by {SignedBy}.",
            http.Request.Method, http.Request.Path, operatorId, string.Join(", ", outcome.SignedBy));
    }

    /// <summary>
    /// Returns the user id only for a token that represents a real, interactively
    /// authenticated administrator.
    ///
    /// <para>
    /// Both conditions matter. The <c>role</c> claim must be present <i>in the token</i>, which
    /// a client-credentials token never has. The subject must also resolve to a real Identity
    /// user, which a client-credentials token's subject — the client ID — does not. Requiring
    /// both closes the contrived case of a client whose ID is spelled like an admin's GUID.
    /// </para>
    /// </summary>
    private async Task<Guid?> ResolveHumanOperatorAsync(AuthorizationFilterContext context)
    {
        var user = context.HttpContext.User;

        if (user?.Identity?.IsAuthenticated != true)
            return null;

        if (!user.HasClaim(Claims.Role, "Admin"))
            return null;

        var subject = user.FindFirst(Claims.Subject)?.Value;
        if (!Guid.TryParse(subject, out var userId))
            return null;

        var identityUser = await userManager.FindByIdAsync(userId.ToString());
        if (identityUser is null)
            return null;

        // Re-check the role against the store rather than trusting the token alone, so a
        // revoked admin cannot keep provisioning until their token expires.
        return await userManager.IsInRoleAsync(identityUser, "Admin") ? userId : null;
    }

    private static async Task<byte[]> ReadBodyAsync(HttpContext http, CancellationToken ct)
    {
        // Authorization filters run before model binding, so nothing has consumed the body yet.
        // Buffering lets the action re-read it after we have hashed it.
        http.Request.EnableBuffering();

        using var buffer = new MemoryStream();
        await http.Request.Body.CopyToAsync(buffer, ct);
        http.Request.Body.Position = 0;

        return buffer.ToArray();
    }

    private async Task AuditAsync(
        Guid? userId, HttpContext http, string action, string details, CancellationToken ct)
    {
        try
        {
            db.AuditLogs.Add(new AuditLog
            {
                Id         = Guid.NewGuid(),
                UserId     = userId,
                Action     = action,
                Details    = $"{http.Request.Method} {http.Request.Path} — {details}",
                IpAddress  = http.Connection.RemoteIpAddress?.ToString(),
                OccurredAt = DateTimeOffset.UtcNow,
            });

            await db.SaveChangesAsync(ct);
        }
        catch (Exception ex)
        {
            // Never let an audit-write failure turn into a 500 that masks the security decision.
            logger.LogError(ex, "Failed to write provisioning audit entry for {Action}.", action);
        }
    }

    private static ObjectResult Problem(
        AuthorizationFilterContext context, int status, string title, string detail) =>
        new(new ProblemDetails
        {
            Status   = status,
            Title    = title,
            Detail   = detail,
            Instance = context.HttpContext.Request.Path,
        })
        { StatusCode = status };
}
