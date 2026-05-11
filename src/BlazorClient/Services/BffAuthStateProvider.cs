using Microsoft.AspNetCore.Components.Authorization;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;

namespace BlazorClient.Services;

public sealed class BffAuthStateProvider(IHttpClientFactory httpClientFactory) : AuthenticationStateProvider
{
    private ClaimsPrincipal _cached = Anonymous();

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        _cached = await FetchUserAsync();
        return new AuthenticationState(_cached);
    }

    public async Task<string?> LoginAsync(string email, string password)
    {
        var http = httpClientFactory.CreateClient("BffClient");
        var response = await http.PostAsJsonAsync("/bff/login", new { email, password });

        if (!response.IsSuccessStatusCode)
        {
            var problem = await response.Content.ReadFromJsonAsync<ErrorResponse>();
            return response.StatusCode switch
            {
                System.Net.HttpStatusCode.Unauthorized => "Invalid email or password.",
                (System.Net.HttpStatusCode)423         => "Account is locked out.",
                _                                      => problem?.Error ?? "Sign in failed. Please try again."
            };
        }

        var userInfo = await response.Content.ReadFromJsonAsync<Dictionary<string, JsonElement>>();
        _cached = BuildPrincipal(userInfo);
        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(_cached)));
        return null; // null = success
    }

    public async Task LogoutAsync()
    {
        var http = httpClientFactory.CreateClient("BffClient");
        await http.PostAsync("/bff/logout", null);
        _cached = Anonymous();
        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(_cached)));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private async Task<ClaimsPrincipal> FetchUserAsync()
    {
        try
        {
            var http = httpClientFactory.CreateClient("BffClient");
            var response = await http.GetAsync("/bff/user");
            if (!response.IsSuccessStatusCode) return Anonymous();

            var userInfo = await response.Content.ReadFromJsonAsync<Dictionary<string, JsonElement>>();
            return BuildPrincipal(userInfo);
        }
        catch
        {
            return Anonymous();
        }
    }

    private static ClaimsPrincipal BuildPrincipal(Dictionary<string, JsonElement>? userInfo)
    {
        if (userInfo is null) return Anonymous();

        var claims = new List<Claim>();
        foreach (var (key, value) in userInfo)
        {
            if (value.ValueKind == JsonValueKind.Array)
                foreach (var item in value.EnumerateArray())
                    claims.Add(new Claim(key, item.ToString()));
            else if (value.ValueKind is not JsonValueKind.Null and not JsonValueKind.Undefined)
                claims.Add(new Claim(key, value.ToString()));
        }

        return new ClaimsPrincipal(new ClaimsIdentity(claims, "bff", "name", "role"));
    }

    private static ClaimsPrincipal Anonymous() => new(new ClaimsIdentity());

    private sealed record ErrorResponse(string? Error);
}
