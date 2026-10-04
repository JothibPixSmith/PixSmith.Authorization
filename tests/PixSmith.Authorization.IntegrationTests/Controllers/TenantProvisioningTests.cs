using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PixSmith.Authorization.Services;
using Xunit;

namespace PixSmith.Authorization.IntegrationTests.Controllers;

/// <summary>
/// Signed tenant provisioning over real HTTP, with genuine ECDSA signatures.
///
/// <para>
/// The unit suite covers the authorizer; these cover the filter that puts it in front of the
/// endpoint. Remove <c>[RequireProvisioningSignature]</c> from a controller action and every
/// unit test still passes while the registry becomes writable by any administrator.
/// </para>
/// </summary>
public sealed class TenantProvisioningTests : IAsyncLifetime
{
    private SecurityWebApplicationFactory _factory = null!;
    private HttpClient _client = null!;
    private string _adminToken = null!;

    private const string Path = "/api/admin/tenants";

    public async Task InitializeAsync()
    {
        _factory = new SecurityWebApplicationFactory();
        _client = _factory.CreateApiClient();

        var response = await _client.PostAsync("/connect/token", new FormUrlEncodedContent(
        [
            new("grant_type", "password"),
            new("username", SecurityWebApplicationFactory.AdminEmail),
            new("password", SecurityWebApplicationFactory.AdminPassword),
            new("client_id", "blazor-client"),
            new("scope", "openid profile email roles api admin"),
        ]));

        response.EnsureSuccessStatusCode();
        _adminToken = (await response.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("access_token").GetString()!;
    }

    public Task DisposeAsync()
    {
        _client.Dispose();
        _factory.Dispose();
        return Task.CompletedTask;
    }

    /// <summary>Signs the canonical payload the server rebuilds, with real keys.</summary>
    private async Task<HttpResponseMessage> CreateTenantAsync(
        string body, params (string KeyId, ECDsa Key)[] signers)
    {
        var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24))
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        var payload = ProvisioningSignature.BuildPayload(
            "POST", Path, nonce, timestamp, Encoding.UTF8.GetBytes(body));

        using var request = new HttpRequestMessage(HttpMethod.Post, Path)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _adminToken);

        if (signers.Length > 0)
        {
            request.Headers.Add(ProvisioningSignature.NonceHeader, nonce);
            request.Headers.Add(ProvisioningSignature.TimestampHeader, timestamp.ToString());

            foreach (var (keyId, key) in signers)
            {
                var signature = key.SignData(
                    Encoding.UTF8.GetBytes(payload), HashAlgorithmName.SHA256,
                    DSASignatureFormat.Rfc3279DerSequence);

                request.Headers.Add(ProvisioningSignature.SignatureHeader,
                    $"{keyId}:{Convert.ToBase64String(signature)}");
            }
        }

        return await _client.SendAsync(request);
    }

    private static string Body(string name) => $"{{\"name\":\"{name}\",\"description\":null}}";

    [Fact]
    public async Task A_quorum_of_distinct_keys_creates_the_tenancy()
    {
        var response = await CreateTenantAsync(Body("Acme Corp"),
            (SecurityWebApplicationFactory.KeyAId, _factory.KeyA),
            (SecurityWebApplicationFactory.KeyBId, _factory.KeyB));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var created = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("acme-corp", created.GetProperty("slug").GetString());
    }

    [Fact]
    public async Task An_administrator_alone_cannot_create_a_tenancy()
    {
        // A valid admin token with no signatures at all.
        var response = await CreateTenantAsync(Body("Unsigned Corp"));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task One_signature_does_not_satisfy_a_quorum_of_two()
    {
        var response = await CreateTenantAsync(Body("One Sig Corp"),
            (SecurityWebApplicationFactory.KeyAId, _factory.KeyA));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task The_same_key_twice_does_not_satisfy_a_quorum_of_two()
    {
        // The point of M-of-N is M distinct holders.
        var response = await CreateTenantAsync(Body("Dup Sig Corp"),
            (SecurityWebApplicationFactory.KeyAId, _factory.KeyA),
            (SecurityWebApplicationFactory.KeyAId, _factory.KeyA));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task A_key_that_is_not_enrolled_is_ignored()
    {
        using var stranger = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var response = await CreateTenantAsync(Body("Stranger Corp"),
            (SecurityWebApplicationFactory.KeyAId, _factory.KeyA),
            ("not-enrolled", stranger));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Signatures_do_not_transfer_to_a_different_body()
    {
        // Signatures are computed over "Acme Corp" but sent with a different payload, as an
        // interceptor would. The body hash is inside the signed material.
        var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24))
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        var signedPayload = ProvisioningSignature.BuildPayload(
            "POST", Path, nonce, timestamp, Encoding.UTF8.GetBytes(Body("Acme Corp")));

        using var request = new HttpRequestMessage(HttpMethod.Post, Path)
        {
            Content = new StringContent(Body("Evil Corp"), Encoding.UTF8, "application/json"),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _adminToken);
        request.Headers.Add(ProvisioningSignature.NonceHeader, nonce);
        request.Headers.Add(ProvisioningSignature.TimestampHeader, timestamp.ToString());

        foreach (var (keyId, key) in new[]
                 {
                     (SecurityWebApplicationFactory.KeyAId, _factory.KeyA),
                     (SecurityWebApplicationFactory.KeyBId, _factory.KeyB),
                 })
        {
            var signature = key.SignData(
                Encoding.UTF8.GetBytes(signedPayload), HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
            request.Headers.Add(ProvisioningSignature.SignatureHeader,
                $"{keyId}:{Convert.ToBase64String(signature)}");
        }

        var response = await _client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task A_machine_identity_cannot_provision_even_with_signatures()
    {
        // The human-interaction requirement, which is independent of the quorum.
        await _factory.RegisterClientAsync(
            "machine-provisioner", ["client_credentials"], ["api", "admin"],
            clientSecret: "machine-secret", confidential: true);

        var tokenResponse = await _client.PostAsync("/connect/token", new FormUrlEncodedContent(
        [
            new("grant_type", "client_credentials"),
            new("client_id", "machine-provisioner"),
            new("client_secret", "machine-secret"),
            new("scope", "api admin"),
        ]));
        tokenResponse.EnsureSuccessStatusCode();

        var machineToken = (await tokenResponse.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("access_token").GetString()!;

        var body = Body("Machine Corp");
        var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24))
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var payload = ProvisioningSignature.BuildPayload(
            "POST", Path, nonce, timestamp, Encoding.UTF8.GetBytes(body));

        using var request = new HttpRequestMessage(HttpMethod.Post, Path)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", machineToken);
        request.Headers.Add(ProvisioningSignature.NonceHeader, nonce);
        request.Headers.Add(ProvisioningSignature.TimestampHeader, timestamp.ToString());

        foreach (var (keyId, key) in new[]
                 {
                     (SecurityWebApplicationFactory.KeyAId, _factory.KeyA),
                     (SecurityWebApplicationFactory.KeyBId, _factory.KeyB),
                 })
        {
            var signature = key.SignData(
                Encoding.UTF8.GetBytes(payload), HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
            request.Headers.Add(ProvisioningSignature.SignatureHeader,
                $"{keyId}:{Convert.ToBase64String(signature)}");
        }

        var response = await _client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Replaying_a_valid_request_is_refused()
    {
        var body = Body("Replay Corp");
        var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24))
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var payload = ProvisioningSignature.BuildPayload(
            "POST", Path, nonce, timestamp, Encoding.UTF8.GetBytes(body));

        var headers = new List<(string, string)>
        {
            (ProvisioningSignature.NonceHeader, nonce),
            (ProvisioningSignature.TimestampHeader, timestamp.ToString()),
        };
        foreach (var (keyId, key) in new[]
                 {
                     (SecurityWebApplicationFactory.KeyAId, _factory.KeyA),
                     (SecurityWebApplicationFactory.KeyBId, _factory.KeyB),
                 })
        {
            var signature = key.SignData(
                Encoding.UTF8.GetBytes(payload), HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
            headers.Add((ProvisioningSignature.SignatureHeader,
                $"{keyId}:{Convert.ToBase64String(signature)}"));
        }

        async Task<HttpStatusCode> SendAsync()
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, Path)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            };
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _adminToken);
            foreach (var (name, value) in headers) request.Headers.Add(name, value);

            var response = await _client.SendAsync(request);
            return response.StatusCode;
        }

        Assert.Equal(HttpStatusCode.Created, await SendAsync());
        Assert.Equal(HttpStatusCode.Forbidden, await SendAsync());
    }
}
