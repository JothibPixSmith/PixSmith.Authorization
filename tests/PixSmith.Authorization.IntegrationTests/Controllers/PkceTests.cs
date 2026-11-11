using System.Net;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PixSmith.Authorization.IntegrationTests.Controllers;

/// <summary>
/// PKCE must be S256. With <c>plain</c> the challenge is the verifier, so anyone who sees the
/// authorization request can redeem the code, which is exactly what PKCE exists to prevent.
/// ASVS 5.0 10.4.6.
///
/// <para>
/// Pinned over HTTP because OpenIddict enables <c>plain</c> by default: the fix is a single
/// options line, and nothing else would notice it being dropped.
/// </para>
/// </summary>
public sealed class PkceTests : IAsyncLifetime
{
    private const string ClientId = "pkce-test-client";
    private const string RedirectUri = "https://client.test/callback";

    // RFC 7636 appendix B test vector: the S256 challenge for its sample verifier.
    private const string S256Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private readonly SecurityWebApplicationFactory _factory = new();
    private HttpClient _client = null!;

    public async Task InitializeAsync()
    {
        _client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost/"),
            AllowAutoRedirect = false,
        });

        using var scope = _factory.Services.CreateScope();
        var apps = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        await apps.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = ClientId,
            ClientType = ClientTypes.Public,
            RedirectUris = { new Uri(RedirectUri) },
            Permissions =
            {
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.ResponseTypes.Code,
                Permissions.Prefixes.Scope + Scopes.OpenId,
            },
            Requirements = { Requirements.Features.ProofKeyForCodeExchange },
        });
    }

    public Task DisposeAsync()
    {
        _client.Dispose();
        _factory.Dispose();
        return Task.CompletedTask;
    }

    [Fact]
    public async Task Plain_code_challenge_method_is_rejected()
    {
        var response = await AuthorizeAsync(("code_challenge", "a-verifier-sent-in-the-clear-0123456789abcdef"),
                                            ("code_challenge_method", "plain"));

        AssertRejectedAtTheServer(response);
    }

    [Fact]
    public async Task Code_challenge_without_a_method_is_rejected()
    {
        // RFC 7636 makes a missing method mean plain, so this is the same downgrade by omission.
        var response = await AuthorizeAsync(("code_challenge", S256Challenge));

        AssertRejectedAtTheServer(response);
    }

    [Fact]
    public async Task S256_reaches_the_login_page()
    {
        var response = await AuthorizeAsync(("code_challenge", S256Challenge),
                                            ("code_challenge_method", "S256"));

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        response.Headers.Location!.ToString().Should().Contain("/Account/Login");
    }

    [Fact]
    public async Task Discovery_advertises_S256_only()
    {
        var json = JsonDocument.Parse(
            await _client.GetStringAsync("/.well-known/openid-configuration")).RootElement;

        json.GetProperty("code_challenge_methods_supported").EnumerateArray()
            .Select(e => e.GetString())
            .Should().Equal("S256");
    }

    private Task<HttpResponseMessage> AuthorizeAsync(params (string Key, string Value)[] pkce)
    {
        var query = new Dictionary<string, string>
        {
            ["client_id"] = ClientId,
            ["redirect_uri"] = RedirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid",
            ["state"] = "state-123",
        };
        foreach (var (key, value) in pkce) query[key] = value;

        var url = "/connect/authorize?" + string.Join("&",
            query.Select(p => $"{p.Key}={Uri.EscapeDataString(p.Value)}"));
        return _client.GetAsync(url);
    }

    /// <summary>
    /// Refused before any login: either an error page from the server, or an error redirect
    /// back to the client. Never the login page, which is what the finding observed.
    /// </summary>
    private static void AssertRejectedAtTheServer(HttpResponseMessage response)
    {
        var location = response.Headers.Location?.ToString() ?? "";
        location.Should().NotContain("/Account/Login", "the request must be refused before sign-in");

        if (response.StatusCode == HttpStatusCode.Redirect)
            location.Should().StartWith(RedirectUri).And.Contain("error=invalid_request");
        else
            response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }
}
