using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.JSInterop;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;

namespace PixSmith.Authorization.BlazorClient.Services;

/// <summary>
/// Manages auth state by:
///   1. POSTing password credentials directly to the OpenIddict /connect/token endpoint.
///   2. Storing the returned encrypted access token in localStorage (used only as a Bearer header).
///   3. Storing the refresh token and expiry time so JwtTokenHandler can proactively refresh.
///   4. Fetching /api/account/me and storing the user snapshot separately — claims are derived
///      from that snapshot, not by parsing the token, because OpenIddict issues JWE tokens
///      that cannot be decoded client-side.
/// </summary>
public sealed class JwtAuthStateProvider(IJSRuntime js, IHttpClientFactory httpClientFactory, IConfiguration configuration)
    : AuthenticationStateProvider
{
    private const string TokenKey    = "access_token";
    private const string RefreshKey  = "refresh_token";
    private const string ExpiryKey   = "token_expiry";   // Unix seconds
    private const string UserInfoKey = "user_info";

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        try
        {
            var token       = await js.InvokeAsync<string?>("localStorage.getItem", TokenKey);
            var userInfoRaw = await js.InvokeAsync<string?>("localStorage.getItem", UserInfoKey);

            if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(userInfoRaw))
                return Anonymous();

            var claims = BuildClaims(userInfoRaw);
            if (claims.Count == 0) return Anonymous();

            var identity = new ClaimsIdentity(claims, "jwt", "name", "role");
            return new AuthenticationState(new ClaimsPrincipal(identity));
        }
        catch
        {
            return Anonymous();
        }
    }

    /// <summary>
    /// Exchanges credentials for a token via the standard OAuth2 password grant, then
    /// fetches the user profile to populate the claims snapshot. Returns null on success,
    /// or a human-readable error message on failure.
    /// </summary>
    public async Task<string?> LoginAsync(string email, string password)
    {
        // Use the no-auth client so JwtTokenHandler is not in the call path for the
        // token endpoint — avoids a potential proactive-refresh loop on first login.
        var http = httpClientFactory.CreateClient("NoAuth");

        var clientId = configuration["Auth:ClientId"]
            ?? throw new InvalidOperationException("Auth:ClientId is required in appsettings.json.");
        var scope = configuration["Auth:Scope"]
            ?? throw new InvalidOperationException("Auth:Scope is required in appsettings.json.");

        using var tokenResponse = await http.PostAsync("connect/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["username"]   = email,
                ["password"]   = password,
                ["scope"]      = scope,
                ["client_id"]  = clientId,
            }));

        if (!tokenResponse.IsSuccessStatusCode)
        {
            JsonElement? errorDoc = null;
            try { errorDoc = await tokenResponse.Content.ReadFromJsonAsync<JsonElement>(); } catch { }

            var desc = errorDoc?.TryGetProperty("error_description", out var d) == true
                ? d.GetString()
                : null;
            return desc ?? "Sign in failed. Please try again.";
        }

        var tokenBody = await tokenResponse.Content.ReadFromJsonAsync<JsonElement>();
        await StoreTokensAsync(tokenBody);

        var accessToken = tokenBody.GetProperty("access_token").GetString()!;

        // Fetch the user profile manually (bypass JwtTokenHandler for this follow-up call).
        using var meRequest = new HttpRequestMessage(HttpMethod.Get, "api/account/me");
        meRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
        var meResponse = await http.SendAsync(meRequest);
        if (!meResponse.IsSuccessStatusCode)
        {
            await ClearStorageAsync();
            return "Signed in but failed to load user profile.";
        }

        var userInfoRaw = await meResponse.Content.ReadAsStringAsync();
        await js.InvokeVoidAsync("localStorage.setItem", UserInfoKey, userInfoRaw);

        var authState = await GetAuthenticationStateAsync();
        NotifyAuthenticationStateChanged(Task.FromResult(authState));
        return null;
    }

    public async Task LogOutAsync()
    {
        await ClearStorageAsync();
        NotifyAuthenticationStateChanged(Task.FromResult(Anonymous()));
    }

    public async Task<string?> GetAccessTokenAsync()
    {
        try
        {
            var token = await js.InvokeAsync<string?>("localStorage.getItem", TokenKey);
            return !string.IsNullOrWhiteSpace(token) ? token : null;
        }
        catch { return null; }
    }

    /// <summary>
    /// Returns true when a stored access token exists and has passed its expiry threshold
    /// (expires_in minus a 60-second buffer). Returns false when no token is stored so
    /// that unauthenticated requests are not confused with expired sessions.
    /// </summary>
    public async Task<bool> IsTokenExpiredAsync()
    {
        try
        {
            var expiryStr = await js.InvokeAsync<string?>("localStorage.getItem", ExpiryKey);
            if (string.IsNullOrEmpty(expiryStr) || !long.TryParse(expiryStr, out var expiry))
                return false; // No stored expiry = not authenticated, don't try to refresh

            return DateTimeOffset.UtcNow.ToUnixTimeSeconds() >= expiry;
        }
        catch { return false; }
    }

    /// <summary>
    /// Exchanges the stored refresh token for a new access token. Returns true on success.
    /// On failure (refresh token expired / revoked) the session is cleared and false is returned.
    /// Uses the "NoAuth" HTTP client to avoid going through JwtTokenHandler.
    /// </summary>
    public async Task<bool> RefreshAsync()
    {
        try
        {
            var refreshToken = await js.InvokeAsync<string?>("localStorage.getItem", RefreshKey);
            if (string.IsNullOrEmpty(refreshToken))
            {
                await LogOutAsync();
                return false;
            }

            var clientId = configuration["Auth:ClientId"]
                ?? throw new InvalidOperationException("Auth:ClientId is required in appsettings.json.");

            var http = httpClientFactory.CreateClient("NoAuth");
            using var response = await http.PostAsync("connect/token",
                new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"]    = "refresh_token",
                    ["refresh_token"] = refreshToken,
                    ["client_id"]     = clientId,
                }));

            if (!response.IsSuccessStatusCode)
            {
                // Refresh token has expired or been revoked — force sign-out.
                await LogOutAsync();
                return false;
            }

            var body = await response.Content.ReadFromJsonAsync<JsonElement>();
            await StoreTokensAsync(body);
            return true;
        }
        catch
        {
            return false;
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private async Task StoreTokensAsync(JsonElement tokenBody)
    {
        var accessToken = tokenBody.GetProperty("access_token").GetString()!;
        await js.InvokeVoidAsync("localStorage.setItem", TokenKey, accessToken);

        if (tokenBody.TryGetProperty("refresh_token", out var rt) && rt.ValueKind == JsonValueKind.String)
            await js.InvokeVoidAsync("localStorage.setItem", RefreshKey, rt.GetString()!);

        // Store expiry as a Unix timestamp with a 60-second safety buffer.
        var expiresIn = tokenBody.TryGetProperty("expires_in", out var exp) ? exp.GetInt32() : 3600;
        var expiry = DateTimeOffset.UtcNow.AddSeconds(expiresIn - 60).ToUnixTimeSeconds();
        await js.InvokeVoidAsync("localStorage.setItem", ExpiryKey, expiry.ToString());
    }

    private async Task ClearStorageAsync()
    {
        await js.InvokeVoidAsync("localStorage.removeItem", TokenKey);
        await js.InvokeVoidAsync("localStorage.removeItem", RefreshKey);
        await js.InvokeVoidAsync("localStorage.removeItem", ExpiryKey);
        await js.InvokeVoidAsync("localStorage.removeItem", UserInfoKey);
    }

    private static AuthenticationState Anonymous() =>
        new(new ClaimsPrincipal(new ClaimsIdentity()));

    private static List<Claim> BuildClaims(string userInfoJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(userInfoJson);
            var root      = doc.RootElement;
            var claims    = new List<Claim>();

            if (root.TryGetProperty("id", out var id))
                claims.Add(new Claim("sub", id.ToString()));
            if (root.TryGetProperty("username", out var name))
                claims.Add(new Claim("name", name.GetString() ?? string.Empty));
            if (root.TryGetProperty("email", out var email))
                claims.Add(new Claim("email", email.GetString() ?? string.Empty));
            if (root.TryGetProperty("roles", out var roles) && roles.ValueKind == JsonValueKind.Array)
                foreach (var role in roles.EnumerateArray())
                    claims.Add(new Claim("role", role.GetString() ?? string.Empty));

            return claims;
        }
        catch
        {
            return [];
        }
    }
}
