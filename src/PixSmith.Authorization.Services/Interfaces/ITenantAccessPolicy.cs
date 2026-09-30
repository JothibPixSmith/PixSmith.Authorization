namespace PixSmith.Authorization.Services.Interfaces;

/// <summary>
/// The outcome of evaluating whether a user may obtain a token for an application.
/// </summary>
/// <param name="IsAllowed">Whether the request may proceed.</param>
/// <param name="Error">
/// A description safe to return in the OAuth <c>error_description</c>. It tells the user
/// something they already know about their own memberships — never anything about companies
/// they do not belong to.
/// </param>
/// <param name="Context">The company context to stamp into the token, when one applies.</param>
public sealed record TenantAccessDecision(bool IsAllowed, string? Error, TenantContext? Context)
{
    public static TenantAccessDecision Allow(TenantContext? context) => new(true, null, context);
    public static TenantAccessDecision Deny(string error) => new(false, error, null);
}

/// <summary>
/// Decides whether a user may reach an application, and in which company context.
/// This is the whole nesting rule of docs/MULTI-TENANCY.md in one place: a member may use an
/// application when their company subscribes to it.
/// </summary>
public interface ITenantAccessPolicy
{
    Task<TenantAccessDecision> EvaluateForUserAsync(
        Guid userId, string? clientId, string? organization, CancellationToken ct = default);
}
