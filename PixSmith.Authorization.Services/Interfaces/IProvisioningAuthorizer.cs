namespace PixSmith.Authorization.Services.Interfaces;

/// <summary>A provisioning request reduced to the values that are covered by the signature.</summary>
public sealed record ProvisioningAttempt(
    string Method,
    string Path,
    string? Nonce,
    string? Timestamp,
    IReadOnlyList<string> SignatureHeaders,
    byte[] Body,
    Guid? SubmittedByUserId);

public sealed record ProvisioningOutcome(bool Authorized, string Reason, IReadOnlyList<string> SignedBy)
{
    public static ProvisioningOutcome Deny(string reason) => new(false, reason, []);
    public static ProvisioningOutcome Allow(IReadOnlyList<string> signedBy) =>
        new(true, "Signature quorum satisfied.", signedBy);
}

public interface IProvisioningAuthorizer
{
    /// <summary>
    /// Verifies the signature quorum and atomically consumes the nonce. Returns a denial
    /// rather than throwing for every failure mode a caller could trigger.
    /// </summary>
    Task<ProvisioningOutcome> AuthorizeAsync(ProvisioningAttempt attempt, CancellationToken ct = default);
}
