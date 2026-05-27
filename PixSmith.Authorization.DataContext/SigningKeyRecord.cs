namespace PixSmith.Authorization.DataContext;

public class SigningKeyRecord
{
    public Guid Id { get; set; }

    /// <summary>JWT "kid" claim — 16-char hex identifier.</summary>
    public string KeyId { get; set; } = string.Empty;

    /// <summary>"Signing" | "Encryption"</summary>
    public string Purpose { get; set; } = string.Empty;

    /// <summary>Algorithm family — matches <c>SigningAlgorithm</c> enum name.</summary>
    public string Algorithm { get; set; } = string.Empty;

    /// <summary>RSA private key bytes, base64-encoded then encrypted via Data Protection.</summary>
    public string EncryptedPrivateKey { get; set; } = string.Empty;

    /// <summary>RSA public key bytes, base64-encoded (plaintext — it's public).</summary>
    public string PublicKeyBase64 { get; set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? RetiredAt { get; set; }

    /// <summary>True for the key that signs new tokens; false for verification-only keys.</summary>
    public bool IsPrimary { get; set; }
}
