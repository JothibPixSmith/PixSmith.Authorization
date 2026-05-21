using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.JSInterop;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;

namespace BlazorClient.Services;

/// <summary>
/// Stores the encrypted access token and a separate user-info snapshot in localStorage.
/// Claims are derived from the user-info snapshot, not by parsing the token, because
/// OpenIddict issues encrypted (JWE) access tokens that cannot be decoded client-side.
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
    /// POST /api/account/login; on success persists the token + user snapshot and
    /// notifies Blazor's auth state cascade. Returns null on success, error message otherwise.
    /// </summary>
    public async Task<string?> LoginAsync(string email, string password)
    {
        try
        {
            var http     = httpClientFactory.CreateClient("AuthAPI");
            var response = await http.PostAsJsonAsync("api/account/login", new { email, password });

            if (!response.IsSuccessStatusCode)
            {
                JsonElement? errorDoc = null;
                try { errorDoc = await response.Content.ReadFromJsonAsync<JsonElement>(); } catch { }

                return response.StatusCode switch
                {
                    System.Net.HttpStatusCode.Unauthorized => "Invalid email or password.",
                    (System.Net.HttpStatusCode)423         => "Account is locked out.",
                    _ => errorDoc?.TryGetProperty("error", out var e) == true
                         ? e.GetString() ?? "Sign in failed."
                         : "Sign in failed. Please try again."
                };
            }

            var body = await response.Content.ReadFromJsonAsync<JsonElement>();

            var token = body.GetProperty("access_token").GetString()!;
            await js.InvokeVoidAsync("localStorage.setItem", TokenKey, token);

            if (body.TryGetProperty("user", out var userProp))
                await js.InvokeVoidAsync("localStorage.setItem", UserInfoKey, userProp.GetRawText());

            var authState = await GetAuthenticationStateAsync();
            NotifyAuthenticationStateChanged(Task.FromResult(authState));
            return null;
        }
        catch
        {
            return "Unable to reach the server. Please try again.";
        }
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
            using var doc  = JsonDocument.Parse(userInfoJson);
            var root       = doc.RootElement;
            var claims     = new List<Claim>();

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
