using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace PixSmith.Authorization.Services;

/// <summary>
/// The canonical string that provisioning signatures are computed over.
///
/// <para>
/// Shared by the server and by operator tooling so there is exactly one definition of what
/// gets signed. Every field that determines the effect of the request is covered: change the
/// tenant name, the target tenant id, or the HTTP verb and the signatures no longer verify.
/// A signature is therefore an authorization of <i>one specific action</i>, not a bearer
/// credential that can be pointed at anything.
/// </para>
/// </summary>
public static class ProvisioningSignature
{
    /// <summary>Bumping this invalidates every previously produced signature by design.</summary>
    public const string Version = "PIXSMITH-TENANT-PROVISION-v1";

    public const string NonceHeader     = "X-Provision-Nonce";
    public const string TimestampHeader = "X-Provision-Timestamp";
    public const string SignatureHeader = "X-Provision-Signature";

    /// <summary>
    /// Builds the canonical payload. Fields are newline-separated; none of them may contain a
    /// newline (the nonce charset is validated, the timestamp is numeric, the body is reduced
    /// to a hex digest), so the encoding is unambiguous and cannot be confused by a crafted
    /// value that splices in extra fields.
    /// </summary>
    public static string BuildPayload(
        string method, string path, string nonce, long unixTimestamp, ReadOnlySpan<byte> body)
    {
        var sb = new StringBuilder();
        sb.Append(Version).Append('\n');
        sb.Append(method.ToUpperInvariant()).Append('\n');
        sb.Append(path).Append('\n');
        sb.Append(nonce).Append('\n');
        sb.Append(unixTimestamp.ToString(CultureInfo.InvariantCulture)).Append('\n');
        sb.Append(Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant());
        return sb.ToString();
    }

    /// <summary>
    /// Nonces are restricted to URL-safe base64 / hex characters so they cannot inject a
    /// newline into the canonical payload. 16 characters is the floor for unguessability.
    /// </summary>
    public static bool IsWellFormedNonce(string? nonce) =>
        !string.IsNullOrEmpty(nonce)
        && nonce.Length is >= 16 and <= 128
        && nonce.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    /// <summary>
    /// Verifies one ECDSA P-256 / SHA-256 signature.
    ///
    /// <para>
    /// Accepts both DER (what <c>openssl dgst -sign</c> emits) and IEEE P1363 fixed-width
    /// r||s (what .NET emits by default), so operators are not forced onto bespoke tooling
    /// to sign a request.
    /// </para>
    /// </summary>
    public static bool Verify(string publicKey, string payload, byte[] signature)
    {
        try
        {
            using var ecdsa = ECDsa.Create();
            ImportPublicKey(ecdsa, publicKey);

            if (ecdsa.KeySize != 256)
                return false;

            var data = Encoding.UTF8.GetBytes(payload);

            return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256,
                       DSASignatureFormat.Rfc3279DerSequence)
                || ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256,
                       DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException)
        {
            // Malformed key or signature is a verification failure, never an error the
            // caller can distinguish from a wrong signature.
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static void ImportPublicKey(ECDsa ecdsa, string publicKey)
    {
        var trimmed = publicKey.Trim();

        if (trimmed.StartsWith("-----BEGIN", StringComparison.Ordinal))
            ecdsa.ImportFromPem(trimmed);
        else
            ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(trimmed), out _);
    }
}
