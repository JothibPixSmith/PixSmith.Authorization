using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.JSInterop;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;

namespace PixSmith.Authorization.BlazorClient.Services;

/// <summary>
/// Manages auth state by:
///   1. POSTing password credentials directly to the OpenIddict /connect/token endpoint.
///   2. Storing the returned encrypted access token in localStorage (used only as a Bearer header).
///   3. Fetching /api/account/me and storing the user snapshot separately — claims are derived
///      from that snapshot, not by parsing the token, because OpenIddict issues JWE tokens
///      that cannot be decoded client-side.
/// </summary>
public sealed class JwtAuthStateProvider(IJSRuntime js, IHttpClientFactory httpClientFactory)
    : AuthenticationStateProvider
{
    private const string TokenKey    = "access_token";
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
        var http = httpClientFactory.CreateClient("AuthAPI");

        // Step 1 — get the encrypted access token from the OpenIddict token endpoint.
        using var tokenResponse = await http.PostAsync("connect/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["username"]   = email,
                ["password"]   = password,
                ["scope"]      = "openid profile email roles offline_access api",
                ["client_id"]  = "blazor-client",
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

        var tokenBody   = await tokenResponse.Content.ReadFromJsonAsync<JsonElement>();
        var accessToken = tokenBody.GetProperty("access_token").GetString()!;

        // Step 2 — persist the token so JwtTokenHandler includes it on the next request.
        await js.InvokeVoidAsync("localStorage.setItem", TokenKey, accessToken);

        // Step 3 — fetch the user profile, attaching the token directly so we don't
        // depend on JwtTokenHandler racing localStorage for this immediate follow-up call.
        using var meRequest = new HttpRequestMessage(HttpMethod.Get, "api/account/me");
        meRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
        var meResponse = await http.SendAsync(meRequest);
        if (!meResponse.IsSuccessStatusCode)
        {
            await js.InvokeVoidAsync("localStorage.removeItem", TokenKey);
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
        await js.InvokeVoidAsync("localStorage.removeItem", TokenKey);
        await js.InvokeVoidAsync("localStorage.removeItem", UserInfoKey);
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

    // ── Helpers ───────────────────────────────────────────────────────────────

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
