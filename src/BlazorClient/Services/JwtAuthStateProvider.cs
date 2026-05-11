using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.JSInterop;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

namespace BlazorClient.Services;

public sealed class JwtAuthStateProvider(IJSRuntime js) : AuthenticationStateProvider
{
	private const string TokenKey = "access_token";

	public override async Task<AuthenticationState> GetAuthenticationStateAsync()
	{
		try
		{
			var token = await js.InvokeAsync<string?>("localStorage.getItem", TokenKey);
			if (string.IsNullOrWhiteSpace(token) || IsExpired(token))
				return Anonymous();

			return Build(token);
		}
		catch
		{
			return Anonymous();
		}
	}

	public async Task MarkAuthenticatedAsync(string accessToken)
	{
		await js.InvokeVoidAsync("localStorage.setItem", TokenKey, accessToken);
		NotifyAuthenticationStateChanged(Task.FromResult(Build(accessToken)));
	}

	public async Task LogOutAsync()
	{
		await js.InvokeVoidAsync("localStorage.removeItem", TokenKey);
		NotifyAuthenticationStateChanged(Task.FromResult(Anonymous()));
	}

	public async Task<string?> GetAccessTokenAsync()
	{
		try
		{
			var token = await js.InvokeAsync<string?>("localStorage.getItem", TokenKey);
			return !string.IsNullOrWhiteSpace(token) && !IsExpired(token) ? token : null;
		}
		catch { return null; }
	}

	// ── Helpers ───────────────────────────────────────────────────────────────

	private static AuthenticationState Build(string token)
	{
		var claims = ParseClaims(token);
		// nameType="name", roleType="role" matches the claim names OpenIddict puts in the JWT
		var identity = new ClaimsIdentity(claims, "jwt", "name", "role");
		return new AuthenticationState(new ClaimsPrincipal(identity));
	}

	private static AuthenticationState Anonymous() =>
		new(new ClaimsPrincipal(new ClaimsIdentity()));

	private static bool IsExpired(string token)
	{
		var claims = ParseClaims(token);
		var exp = claims.FirstOrDefault(c => c.Type == "exp")?.Value;
		return exp is null
			|| !long.TryParse(exp, out var expSeconds)
			|| DateTimeOffset.UtcNow.ToUnixTimeSeconds() >= expSeconds;
	}

	private static List<Claim> ParseClaims(string token)
	{
		var parts = token.Split('.');
		if (parts.Length < 2) return [];

		var payload = parts[1].Replace('-', '+').Replace('_', '/');
		payload = (payload.Length % 4) switch
		{
			2 => payload + "==",
			3 => payload + "=",
			_ => payload
		};

		var json = Encoding.UTF8.GetString(Convert.FromBase64String(payload));
		using var doc = JsonDocument.Parse(json);

		var claims = new List<Claim>();
		foreach (var prop in doc.RootElement.EnumerateObject())
		{
			if (prop.Value.ValueKind == JsonValueKind.Array)
				foreach (var item in prop.Value.EnumerateArray())
					claims.Add(new Claim(prop.Name, item.ToString()));
			else
				claims.Add(new Claim(prop.Name, prop.Value.ToString()));
		}
		return claims;
	}
}
