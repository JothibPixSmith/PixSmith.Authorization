using PixSmith.Authorization.Services;
using Xunit;

namespace PixSmith.Authorization.UnitTests.Services;

/// <summary>
/// Vetting of client-assertion key sets. The point of client assertions is that the server
/// never holds anything able to impersonate the client, so the rules here are about keeping
/// private material out — not about convenience.
/// </summary>
public sealed class JsonWebKeySetValidatorTests
{
    private const string PublicEc = """
        {"keys":[{"kty":"EC","crv":"P-256","kid":"k1","use":"sig","alg":"ES256",
                  "x":"gMjXHvZyv-CvwpOtjc2lGndYb0hQ0mQ5RzVCa1RrT0E",
                  "y":"bFhKUmpRY0hRb1VkVWJkcE5SS0dCZkhMdmpwWUZ4WTQ"}]}
        """;

    [Fact]
    public void A_public_key_set_is_accepted()
    {
        var result = JsonWebKeySetValidator.Validate(PublicEc);

        Assert.True(result.IsSuccess);
        Assert.Equal("k1", result.Value!.Keys.Single().Kid);
    }

    [Theory]
    [InlineData("d")]
    [InlineData("p")]
    [InlineData("q")]
    [InlineData("dp")]
    [InlineData("dq")]
    [InlineData("qi")]
    public void Private_components_are_refused(string component)
    {
        // Refused, never stripped: silently accepting a request in which someone pasted their
        // private key would leave them believing it was never exposed.
        var json = $$"""
            {"keys":[{"kty":"EC","crv":"P-256","kid":"k1","use":"sig",
                      "x":"gMjXHvZyv-CvwpOtjc2lGndYb0hQ0mQ5RzVCa1RrT0E",
                      "y":"bFhKUmpRY0hRb1VkVWJkcE5SS0dCZkhMdmpwWUZ4WTQ",
                      "{{component}}":"c29tZS1wcml2YXRlLXZhbHVl"}]}
            """;

        var result = JsonWebKeySetValidator.Validate(json);

        Assert.False(result.IsSuccess);
        Assert.Contains("private key material", result.Error);
        Assert.Contains(component, result.Error);
    }

    [Fact]
    public void A_symmetric_key_is_refused()
    {
        // Otherwise it is a shared secret wearing a JWKS costume — every property the design
        // is trying to gain would be lost.
        var result = JsonWebKeySetValidator.Validate("""{"keys":[{"kty":"oct","kid":"s1","k":"c2VjcmV0"}]}""");

        Assert.False(result.IsSuccess);
    }

    [Fact]
    public void An_encryption_key_is_refused()
    {
        var json = PublicEc.Replace("\"use\":\"sig\"", "\"use\":\"enc\"");

        var result = JsonWebKeySetValidator.Validate(json);

        Assert.False(result.IsSuccess);
        Assert.Contains("use 'sig'", result.Error);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void A_missing_key_set_is_refused(string? json)
    {
        Assert.False(JsonWebKeySetValidator.Validate(json).IsSuccess);
    }

    [Fact]
    public void Unparseable_json_is_refused()
    {
        Assert.False(JsonWebKeySetValidator.Validate("not json at all").IsSuccess);
    }

    [Fact]
    public void An_empty_key_set_is_refused()
    {
        var result = JsonWebKeySetValidator.Validate("""{"keys":[]}""");

        Assert.False(result.IsSuccess);
        Assert.Contains("no keys", result.Error);
    }
}
