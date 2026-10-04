using System.Security.Cryptography.X509Certificates;
using OpenIddict.Server;

namespace PixSmith.Authorization.API.Security;

/// <summary>
/// Loads the X.509 certificates OpenIddict signs and encrypts tokens with.
///
/// <para>
/// Ephemeral keys are regenerated on every start, so each restart invalidates every token in
/// every integrated application and rotates the published JWKS out from under their
/// validators. That is tolerable for a single local instance and unacceptable anywhere real,
/// so outside development this configuration is <b>required</b> and startup fails without it.
/// </para>
///
/// <para>
/// Failing to start is the point. The alternative — quietly falling back to ephemeral keys —
/// produces a deployment that works in testing and then signs everybody out at the next
/// restart, which is far harder to diagnose than a refusal at boot.
/// </para>
/// </summary>
public static class OpenIddictCertificates
{
    public const string SectionName = "OpenIddict:Certificates";

    public static void Configure(
        OpenIddictServerBuilder options, IConfiguration configuration, IHostEnvironment environment)
    {
        var section = configuration.GetSection(SectionName);

        var signing = Load(section.GetSection("Signing"), "signing");
        var encryption = Load(section.GetSection("Encryption"), "encryption");

        if (signing is not null && encryption is not null)
        {
            options.AddSigningCertificate(signing)
                   .AddEncryptionCertificate(encryption);
            return;
        }

        if (signing is not null || encryption is not null)
        {
            throw new InvalidOperationException(
                $"Only one of {SectionName}:Signing and {SectionName}:Encryption is configured. " +
                "Configure both or neither — a half-configured pair would silently fall back to " +
                "ephemeral keys for the other half.");
        }

        // Development and Testing may run without certificates. Everything else may not.
        if (environment.IsDevelopment() || environment.IsEnvironment("Testing"))
        {
            if (environment.IsDevelopment())
            {
                options.AddDevelopmentEncryptionCertificate()
                       .AddDevelopmentSigningCertificate();
            }
            else
            {
                options.AddEphemeralEncryptionKey()
                       .AddEphemeralSigningKey();
            }

            return;
        }

        throw new InvalidOperationException(
            $"""
            No token certificates are configured and the environment is '{environment.EnvironmentName}'.

            Ephemeral keys would invalidate every issued token on each restart and rotate the
            JWKS out from under every integrated application, so startup is refused instead.

            Configure both, as a file path or base64-encoded PKCS#12:

              {SectionName}:Signing:Path        /run/secrets/signing.pfx
              {SectionName}:Signing:Password    <password>
              {SectionName}:Encryption:Path     /run/secrets/encryption.pfx
              {SectionName}:Encryption:Password <password>

            or {SectionName}:Signing:Base64 / :Encryption:Base64 for secret stores that only
            carry strings. Generate a pair with:

              openssl req -x509 -newkey rsa:2048 -keyout k.pem -out c.pem -days 3650 -nodes \
                -subj "/CN=PixSmith Authorization Signing"
              openssl pkcs12 -export -inkey k.pem -in c.pem -out signing.pfx -passout pass:<password>

            Use separate certificates for signing and encryption, and keep them across
            deployments — replacing them has the same effect as an ephemeral key.
            """);
    }

    private static X509Certificate2? Load(IConfigurationSection section, string purpose)
    {
        var path = section["Path"];
        var base64 = section["Base64"];
        var password = section["Password"];

        if (string.IsNullOrWhiteSpace(path) && string.IsNullOrWhiteSpace(base64))
            return null;

        if (!string.IsNullOrWhiteSpace(path) && !string.IsNullOrWhiteSpace(base64))
        {
            throw new InvalidOperationException(
                $"The {purpose} certificate specifies both Path and Base64. Use one.");
        }

        try
        {
            // EphemeralKeySet keeps the private key out of the filesystem, which matters in a
            // container whose key store is not persisted and may not be writable at all.
            const X509KeyStorageFlags flags = X509KeyStorageFlags.EphemeralKeySet;

            var certificate = !string.IsNullOrWhiteSpace(path)
                ? X509CertificateLoader.LoadPkcs12FromFile(path, password, flags)
                : X509CertificateLoader.LoadPkcs12(Convert.FromBase64String(base64!), password, flags);

            if (!certificate.HasPrivateKey)
            {
                throw new InvalidOperationException(
                    $"The {purpose} certificate has no private key. Export it as PKCS#12 including " +
                    "the key, not as a bare public certificate.");
            }

            return certificate;
        }
        catch (Exception ex) when (ex is not InvalidOperationException)
        {
            throw new InvalidOperationException(
                $"The {purpose} certificate could not be loaded: {ex.Message}", ex);
        }
    }
}
