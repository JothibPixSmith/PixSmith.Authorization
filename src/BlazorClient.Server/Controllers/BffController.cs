using Microsoft.AspNetCore.Mvc;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace PixSmith.Authorization.BlazorClient.Server.Controllers;

[ApiController]
[Route("bff")]
public sealed class BffController(IHttpClientFactory httpClientFactory, IConfiguration config) : ControllerBase
{
    private const string TokenKey      = "access_token";
    private const string PkceVerifier  = "pkce_verifier";
    private const string OAuthState    = "oauth_state";

    // ─── Login (ROPC — form-based) ────────────────────────────────────────────

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var http = httpClientFactory.CreateClient("AuthServer");

        var tokenResponse = await http.PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"]    = "password",
                ["username"]      = request.Email,
                ["password"]      = request.Password,
                ["scope"]         = "openid profile email roles api offline_access",
                ["client_id"]     = "blazor-bff",
                ["client_secret"] = config["BffClient:Secret"] ?? string.Empty,
            }));

        var tokenJson = await tokenResponse.Content.ReadAsStringAsync();

        if (!tokenResponse.IsSuccessStatusCode)
        {
            using var errDoc = JsonDocument.Parse(tokenJson);
            var errorCode = errDoc.RootElement.TryGetProperty("error", out var e) ? e.GetString() : null;
            return errorCode switch
            {
                "invalid_grant" => Unauthorized(new { error = "Invalid email or password." }),
                _               => StatusCode((int)tokenResponse.StatusCode, new { error = errorCode ?? "Login failed." })
            };
        }

        using var doc = JsonDocument.Parse(tokenJson);

        if (!doc.RootElement.TryGetProperty("access_token", out var tokenElement) ||
            string.IsNullOrEmpty(tokenElement.GetString()))
            return StatusCode(StatusCodes.Status502BadGateway, new { error = "AuthServer returned no token." });

        HttpContext.Session.SetString(TokenKey, tokenElement.GetString()!);

        var userInfo = await FetchUserInfoAsync(tokenElement.GetString()!);
        return userInfo is null
            ? StatusCode(StatusCodes.Status502BadGateway, new { error = "Failed to retrieve user info." })
            : Ok(userInfo);
    }

    // ─── SSO — initiation (redirect through BFF) ─────────────────────────────
    // Browser navigates here; BFF bounces to AuthServer external-login with a
    // returnUrl pointing back to /connect/authorize so OpenIddict issues a code.

    [HttpGet("external-login")]
    public IActionResult ExternalLogin(string provider)
    {
        var authServer = AuthServerBaseUrl();
        var bff        = BffBaseUrl();

        var codeVerifier  = GenerateCodeVerifier();
        var codeChallenge = GenerateCodeChallenge(codeVerifier);
        var state         = GenerateRandomBase64Url(16);

        HttpContext.Session.SetString(PkceVerifier, codeVerifier);
        HttpContext.Session.SetString(OAuthState, state);

        var redirectUri = $"{bff}/bff/sso-callback";
        var scope       = "openid profile email roles api offline_access";

        // Relative authorize URL so AuthServer's LocalRedirect accepts it
        var authorizeUrl =
            "/connect/authorize" +
            "?client_id=blazor-bff" +
            "&response_type=code" +
            $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
            $"&scope={Uri.EscapeDataString(scope)}" +
            $"&state={Uri.EscapeDataString(state)}" +
            $"&code_challenge={Uri.EscapeDataString(codeChallenge)}" +
            "&code_challenge_method=S256";

        var externalLoginUrl =
            $"{authServer}/api/account/external-login" +
            $"?provider={Uri.EscapeDataString(provider)}" +
            $"&returnUrl={Uri.EscapeDataString(authorizeUrl)}";

        return Redirect(externalLoginUrl);
    }

    // ─── SSO — callback (code → token → session) ─────────────────────────────
    // OpenIddict redirects here after the authorization code is issued.

    [HttpGet("sso-callback")]
    public async Task<IActionResult> SsoCallback(string? code, string? state, string? error)
    {
        var blazorUrl = config["Blazor:BaseUrl"] ?? "https://localhost:7200";

        if (error is not null || code is null)
            return Redirect($"{blazorUrl}/login?error={Uri.EscapeDataString(error ?? "sso_failed")}");

        var storedState   = HttpContext.Session.GetString(OAuthState);
        var codeVerifier  = HttpContext.Session.GetString(PkceVerifier);

        HttpContext.Session.Remove(OAuthState);
        HttpContext.Session.Remove(PkceVerifier);

        if (storedState is null || storedState != state)
            return Redirect($"{blazorUrl}/login?error=state_mismatch");

        if (codeVerifier is null)
            return Redirect($"{blazorUrl}/login?error=missing_verifier");

        var bff  = BffBaseUrl();
        var http = httpClientFactory.CreateClient("AuthServer");

        var tokenResponse = await http.PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"]    = "authorization_code",
                ["code"]          = code,
                ["redirect_uri"]  = $"{bff}/bff/sso-callback",
                ["client_id"]     = "blazor-bff",
                ["client_secret"] = config["BffClient:Secret"] ?? string.Empty,
                ["code_verifier"] = codeVerifier,
            }));

        if (!tokenResponse.IsSuccessStatusCode)
            return Redirect($"{blazorUrl}/login?error=token_exchange_failed");

        using var doc = JsonDocument.Parse(await tokenResponse.Content.ReadAsStringAsync());

        if (!doc.RootElement.TryGetProperty("access_token", out var tokenEl) ||
            string.IsNullOrEmpty(tokenEl.GetString()))
            return Redirect($"{blazorUrl}/login?error=no_token");

        HttpContext.Session.SetString(TokenKey, tokenEl.GetString()!);
        return Redirect($"{blazorUrl}/admin");
    }

    // ─── Logout ───────────────────────────────────────────────────────────────

    [HttpPost("logout")]
    public IActionResult Logout()
    {
        HttpContext.Session.Clear();
        return Ok();
    }

    // ─── User Info ────────────────────────────────────────────────────────────

    [HttpGet("user")]
    public async Task<IActionResult> GetUser()
    {
        var token = HttpContext.Session.GetString(TokenKey);
        if (string.IsNullOrEmpty(token))
            return Unauthorized();

        var userInfo = await FetchUserInfoAsync(token);
        return userInfo is null ? Unauthorized() : Ok(userInfo);
    }

    // ─── Proxy ────────────────────────────────────────────────────────────────
    // Forwards any API call to AuthServer, injecting the session's access token.

    [HttpGet("proxy/{**path}")]
    [HttpPost("proxy/{**path}")]
    [HttpPut("proxy/{**path}")]
    [HttpPatch("proxy/{**path}")]
    [HttpDelete("proxy/{**path}")]
    public async Task<IActionResult> Proxy(string path)
    {
        var token = HttpContext.Session.GetString(TokenKey);
        if (string.IsNullOrEmpty(token))
            return Unauthorized();

        var targetUrl = $"{AuthServerBaseUrl()}/{path}{Request.QueryString}";
        var http      = httpClientFactory.CreateClient("AuthServer");

        var upstream = new HttpRequestMessage(new HttpMethod(Request.Method), targetUrl);
        upstream.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        if (HttpMethods.IsPost(Request.Method) ||
            HttpMethods.IsPut(Request.Method)  ||
            HttpMethods.IsPatch(Request.Method))
        {
            upstream.Content = new StreamContent(Request.Body);
            if (Request.ContentType is not null)
                upstream.Content.Headers.TryAddWithoutValidation("Content-Type", Request.ContentType);
        }

        var response = await http.SendAsync(upstream);
        var content  = await response.Content.ReadAsStringAsync();

        return new ContentResult
        {
            StatusCode  = (int)response.StatusCode,
            Content     = content,
            ContentType = response.Content.Headers.ContentType?.ToString() ?? "application/json",
        };
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private string AuthServerBaseUrl() =>
        (config["AuthServer:BaseUrl"] ?? "https://localhost:7100").TrimEnd('/');

    private string BffBaseUrl() =>
        (config["Bff:BaseUrl"] ?? "https://localhost:7300").TrimEnd('/');

    private async Task<Dictionary<string, JsonElement>?> FetchUserInfoAsync(string accessToken)
    {
        var http = httpClientFactory.CreateClient("AuthServer");
        using var req = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        var response = await http.SendAsync(req);
        if (!response.IsSuccessStatusCode) return null;

        return await response.Content.ReadFromJsonAsync<Dictionary<string, JsonElement>>();
    }

    private static string GenerateCodeVerifier() => GenerateRandomBase64Url(32);

    private static string GenerateCodeChallenge(string verifier)
    {
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        return Base64UrlEncode(hash);
    }

    private static string GenerateRandomBase64Url(int byteLength)
    {
        var bytes = new byte[byteLength];
        RandomNumberGenerator.Fill(bytes);
        return Base64UrlEncode(bytes);
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

public sealed record LoginRequest(string Email, string Password);
