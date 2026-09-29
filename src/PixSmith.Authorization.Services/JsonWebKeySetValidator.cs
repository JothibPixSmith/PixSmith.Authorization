using Microsoft.IdentityModel.Tokens;
using PixSmith.Authorization.Domain.Results;

namespace PixSmith.Authorization.Services;

/// <summary>
/// Parses and vets a client's JWKS before it is registered for client-assertion
/// (<c>private_key_jwt</c>) authentication.
///
/// <para>
/// The point of client assertions is that the server never holds a credential capable of
/// impersonating the client. A JWKS containing private key material would silently undo
/// that — so the strictest rule here is that private components are refused outright rather
/// than stripped. Stripping would accept a request in which someone has just pasted their
/// private key into an HTTP body, and say nothing about it.
/// </para>
/// </summary>
public static class JsonWebKeySetValidator
{
    /// <summary>Private and symmetric components. Any of these means this is not a public key.</summary>
    private static readonly (string Name, Func<JsonWebKey, string?> Get)[] PrivateComponents =
    [
        ("d",  k => k.D),    // RSA private exponent / EC private key
        ("p",  k => k.P),
        ("q",  k => k.Q),
        ("dp", k => k.DP),
        ("dq", k => k.DQ),
        ("qi", k => k.QI),
        ("k",  k => k.K),    // symmetric key material
    ];

    public static Result<JsonWebKeySet> Validate(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return Result<JsonWebKeySet>.Failure("A JSON Web Key Set is required.");

        JsonWebKeySet keySet;
        try
        {
            keySet = JsonWebKeySet.Create(json);
        }
        catch (Exception ex)
        {
            return Result<JsonWebKeySet>.Failure($"The JSON Web Key Set could not be parsed: {ex.Message}");
        }

        if (keySet.Keys.Count == 0)
            return Result<JsonWebKeySet>.Failure("The JSON Web Key Set contains no keys.");

        foreach (var key in keySet.Keys)
        {
            var label = string.IsNullOrWhiteSpace(key.Kid) ? "(no kid)" : $"'{key.Kid}'";

            var leaked = PrivateComponents
                .Where(c => !string.IsNullOrWhiteSpace(c.Get(key)))
                .Select(c => c.Name)
                .ToList();

            if (leaked.Count > 0)
            {
                return Result<JsonWebKeySet>.Failure(
                    $"Key {label} contains private key material ({string.Join(", ", leaked)}). " +
                    "Register the public half only — export it with a tool that strips private " +
                    "components. Treat the key you pasted as compromised and generate a new one.");
            }

            // OpenIddict verifies client assertions with RSA or ECDSA keys; a symmetric key
            // here would be a shared secret wearing a JWKS costume.
            if (!string.Equals(key.Kty, JsonWebAlgorithmsKeyTypes.RSA, StringComparison.Ordinal)
                && !string.Equals(key.Kty, JsonWebAlgorithmsKeyTypes.EllipticCurve, StringComparison.Ordinal))
            {
                return Result<JsonWebKeySet>.Failure(
                    $"Key {label} has key type '{key.Kty}'. Client assertions require an RSA or EC key.");
            }

            if (!string.IsNullOrWhiteSpace(key.Use)
                && !string.Equals(key.Use, JsonWebKeyUseNames.Sig, StringComparison.Ordinal))
            {
                return Result<JsonWebKeySet>.Failure(
                    $"Key {label} declares use '{key.Use}'. Client assertion keys must have use 'sig'.");
            }
        }

        return Result<JsonWebKeySet>.Success(keySet);
    }
}
