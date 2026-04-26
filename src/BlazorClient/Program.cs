using BlazorClient;
using BlazorClient.Services;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Authentication;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

// ─── OIDC Authentication ──────────────────────────────────────────────────────

builder.Services.AddOidcAuthentication(options =>
{
	options.ProviderOptions.Authority = builder.Configuration["Auth:Authority"]
		?? "https://localhost:7100";

	options.ProviderOptions.ClientId = builder.Configuration["Auth:ClientId"]
		?? "blazor-client";

	options.ProviderOptions.RedirectUri = "https://localhost:7200/authentication/login-callback";
	options.ProviderOptions.PostLogoutRedirectUri = "https://localhost:7200/authentication/logout-callback";

	options.ProviderOptions.ResponseType = "code"; // Authorization Code + PKCE

	options.ProviderOptions.DefaultScopes.Add("email");
	options.ProviderOptions.DefaultScopes.Add("roles");
	options.ProviderOptions.DefaultScopes.Add("api");
	options.ProviderOptions.DefaultScopes.Add("offline_access");

	options.UserOptions.RoleClaim = "role";
});

// ─── HTTP Client ──────────────────────────────────────────────────────────────

// AuthorizationMessageHandler (not BaseAddressAuthorizationMessageHandler) is required
// because the API runs on a different origin (7100) than the Blazor app (7200).
var apiBaseUrl = builder.Configuration["ApiBaseUrl"] ?? "https://localhost:7100";

builder.Services.AddHttpClient("AuthAPI",
	client => client.BaseAddress = new Uri(apiBaseUrl))
	.AddHttpMessageHandler(sp =>
		sp.GetRequiredService<AuthorizationMessageHandler>()
		  .ConfigureHandler(authorizedUrls: [apiBaseUrl], scopes: ["openid", "profile", "api"]));

// Unauthenticated client — used for login/register before tokens exist
builder.Services.AddHttpClient("Public", client => client.BaseAddress = new Uri(apiBaseUrl));

// Named scoped service to inject the client
builder.Services.AddScoped(sp => sp.GetRequiredService<IHttpClientFactory>().CreateClient("AuthAPI"));

// ─── App Services ─────────────────────────────────────────────────────────────

builder.Services.AddScoped<IAdminApiService, AdminApiService>();
builder.Services.AddScoped<IAccountApiService, AccountApiService>();

await builder.Build().RunAsync();
