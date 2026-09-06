namespace PixSmith.Authorization.Services;

/// <summary>
/// Trust anchor for tenant provisioning.
///
/// <para>
/// These keys deliberately live in configuration / the secret store and <b>never</b> in the
/// database. A registry whose own trust anchor is stored in the registry is not protected:
/// anyone who can write to the database would simply enrol their own key and sign whatever
/// they liked. Config placement means bypassing the control requires compromising the
/// deployment pipeline, not just SQL access.
/// </para>
/// </summary>
public sealed class TenantProvisioningOptions
{
    public const string SectionName = "TenantProvisioning";

    /// <summary>
    /// Number of <b>distinct</b> enrolled keys that must sign a request. Defaults to 2 so a
    /// single stolen key, or a single rogue operator, cannot provision a tenancy alone.
    /// </summary>
    public int RequiredSignatures { get; set; } = 2;

    /// <summary>
    /// How far a request timestamp may be from server time. Bounds the window in which a
    /// captured request is useful; the single-use nonce is what actually stops replay.
    /// </summary>
    public int MaxClockSkewSeconds { get; set; } = 300;

    public List<ProvisioningKey> Keys { get; set; } = [];

    /// <summary>
    /// Keys eligible to sign right now. There is deliberately no "disable the whole check"
    /// switch — if this returns fewer keys than <see cref="RequiredSignatures"/>, provisioning
    /// fails closed.
    /// </summary>
    public IReadOnlyList<ProvisioningKey> UsableKeys(DateTimeOffset now) =>
        Keys.Where(k => k.IsUsableAt(now)).ToList();
}

public sealed record ProvisioningKey
{
    /// <summary>Stable identifier quoted in the signature header and the audit trail.</summary>
    public string KeyId { get; set; } = string.Empty;

    /// <summary>Named human who physically holds the private key. Recorded in the audit log.</summary>
    public string Holder { get; set; } = string.Empty;

    /// <summary>ECDSA P-256 public key, PEM ("-----BEGIN PUBLIC KEY-----") or bare base64 SPKI.</summary>
    public string PublicKey { get; set; } = string.Empty;

    public bool Disabled { get; set; }
    public DateTimeOffset? NotBefore { get; set; }
    public DateTimeOffset? NotAfter { get; set; }

    public bool IsUsableAt(DateTimeOffset now) =>
        !Disabled
        && !string.IsNullOrWhiteSpace(KeyId)
        && !string.IsNullOrWhiteSpace(PublicKey)
        && (NotBefore is null || now >= NotBefore)
        && (NotAfter is null || now <= NotAfter);
}
