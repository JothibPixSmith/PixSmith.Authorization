using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Services.Interfaces;

namespace PixSmith.Authorization.Services;

/// <summary>
/// Enforces the M-of-N offline signature quorum for tenant provisioning.
///
/// <para>
/// Denials are deliberately coarse in what they report back to the caller — enough to debug a
/// legitimate misconfiguration, not enough to let an attacker probe which key IDs are enrolled
/// or which of several signatures failed. The full detail goes to the log.
/// </para>
/// </summary>
public sealed class ProvisioningAuthorizer(
    ApplicationDbContext db,
    IOptions<TenantProvisioningOptions> options,
    TimeProvider timeProvider,
    ILogger<ProvisioningAuthorizer> logger) : IProvisioningAuthorizer
{
    public async Task<ProvisioningOutcome> AuthorizeAsync(
        ProvisioningAttempt attempt, CancellationToken ct = default)
    {
        var opts = options.Value;
        var now = timeProvider.GetUtcNow();

        // ── Trust anchor must be able to satisfy the quorum at all ────────────────
        // Fail closed: an unconfigured or under-configured server refuses to provision
        // rather than falling back to "admin token is enough".

        if (opts.RequiredSignatures < 1)
        {
            logger.LogError(
                "TenantProvisioning:RequiredSignatures is {Count}; refusing to provision. " +
                "This control cannot be switched off by configuration.", opts.RequiredSignatures);
            return ProvisioningOutcome.Deny("Tenant provisioning is not correctly configured.");
        }

        var usableKeys = opts.UsableKeys(now);
        if (usableKeys.Count < opts.RequiredSignatures)
        {
            logger.LogError(
                "Tenant provisioning denied: {Usable} usable signing key(s) configured but " +
                "{Required} signature(s) required.", usableKeys.Count, opts.RequiredSignatures);
            return ProvisioningOutcome.Deny("Tenant provisioning is not correctly configured.");
        }

        // Duplicate key IDs in configuration would let one physical key be counted twice
        // and silently collapse the quorum to a single holder.
        var duplicateKeyIds = usableKeys
            .GroupBy(k => k.KeyId, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToList();

        if (duplicateKeyIds.Count > 0)
        {
            logger.LogError(
                "Tenant provisioning denied: duplicate key IDs in configuration ({KeyIds}).",
                string.Join(", ", duplicateKeyIds));
            return ProvisioningOutcome.Deny("Tenant provisioning is not correctly configured.");
        }

        // ── Freshness ─────────────────────────────────────────────────────────────

        if (!ProvisioningSignature.IsWellFormedNonce(attempt.Nonce))
            return ProvisioningOutcome.Deny($"A well-formed {ProvisioningSignature.NonceHeader} header is required.");

        if (!long.TryParse(attempt.Timestamp, out var unixTimestamp))
            return ProvisioningOutcome.Deny($"A numeric {ProvisioningSignature.TimestampHeader} header is required.");

        var signedAt = DateTimeOffset.FromUnixTimeSeconds(unixTimestamp);
        var skew = (now - signedAt).Duration();
        if (skew > TimeSpan.FromSeconds(opts.MaxClockSkewSeconds))
            return ProvisioningOutcome.Deny(
                $"Request timestamp is outside the permitted {opts.MaxClockSkewSeconds}s window.");

        if (attempt.SignatureHeaders.Count == 0)
            return ProvisioningOutcome.Deny($"At least one {ProvisioningSignature.SignatureHeader} header is required.");

        // ── Signature verification ────────────────────────────────────────────────

        var payload = ProvisioningSignature.BuildPayload(
            attempt.Method, attempt.Path, attempt.Nonce!, unixTimestamp, attempt.Body);

        var verifiedKeyIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var header in attempt.SignatureHeaders)
        {
            var separator = header.IndexOf(':');
            if (separator <= 0 || separator == header.Length - 1)
                return ProvisioningOutcome.Deny($"Malformed {ProvisioningSignature.SignatureHeader} header.");

            var keyId = header[..separator].Trim();
            var signatureText = header[(separator + 1)..].Trim();

            byte[] signature;
            try
            {
                // Accept both base64 and base64url so operators can paste from either tool.
                signature = Convert.FromBase64String(
                    signatureText.Replace('-', '+').Replace('_', '/').PadRight(
                        signatureText.Length + (4 - signatureText.Length % 4) % 4, '='));
            }
            catch (FormatException)
            {
                return ProvisioningOutcome.Deny($"Malformed {ProvisioningSignature.SignatureHeader} header.");
            }

            var key = usableKeys.FirstOrDefault(k =>
                string.Equals(k.KeyId, keyId, StringComparison.OrdinalIgnoreCase));

            if (key is null)
            {
                logger.LogWarning(
                    "Tenant provisioning: signature presented for unknown or expired key ID {KeyId}.", keyId);
                continue;
            }

            if (!ProvisioningSignature.Verify(key.PublicKey, payload, signature))
            {
                logger.LogWarning(
                    "Tenant provisioning: signature for key {KeyId} ({Holder}) failed to verify.",
                    key.KeyId, key.Holder);
                continue;
            }

            // A HashSet keyed on KeyId is what makes the quorum mean "M distinct holders" —
            // presenting the same valid signature M times must not satisfy it.
            verifiedKeyIds.Add(key.KeyId);
        }

        if (verifiedKeyIds.Count < opts.RequiredSignatures)
        {
            logger.LogWarning(
                "Tenant provisioning denied for {Method} {Path}: {Verified} of {Required} required " +
                "signatures verified.", attempt.Method, attempt.Path,
                verifiedKeyIds.Count, opts.RequiredSignatures);

            return ProvisioningOutcome.Deny(
                $"{opts.RequiredSignatures} valid signatures from distinct provisioning keys are " +
                $"required; {verifiedKeyIds.Count} verified.");
        }

        // ── Consume the nonce ─────────────────────────────────────────────────────
        // Only now, once the signatures are known good, so a failed or hostile attempt
        // cannot burn a nonce the legitimate operators are about to use.

        var signedBy = verifiedKeyIds.OrderBy(k => k, StringComparer.OrdinalIgnoreCase).ToList();

        db.ProvisioningNonces.Add(new ProvisioningNonce
        {
            Id        = Guid.NewGuid(),
            Nonce     = attempt.Nonce!,
            Operation = $"{attempt.Method.ToUpperInvariant()} {attempt.Path}",
            SignedBy  = string.Join(",", signedBy),
            UserId    = attempt.SubmittedByUserId,
            UsedAt    = now,
        });

        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            // The unique index rejected it: this nonce has already been spent. Two concurrent
            // replays both reach here and exactly one wins.
            db.ChangeTracker.Clear();
            logger.LogWarning(
                "Tenant provisioning denied: nonce replay detected for {Method} {Path}.",
                attempt.Method, attempt.Path);
            return ProvisioningOutcome.Deny("This provisioning nonce has already been used.");
        }

        return ProvisioningOutcome.Allow(signedBy);
    }
}
