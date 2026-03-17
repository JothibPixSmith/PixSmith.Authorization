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
    // These mirror the OpenIddict client seeded server-side
    options.ProviderOptions.Authority = builder.Configuration["Auth:Authority"]
        ?? "https://localhost:7100";

    options.ProviderOptions.ClientId = builder.Configuration["Auth:ClientId"]
        ?? "blazor-client";

    options.ProviderOptions.ResponseType = "code"; // Authorization Code + PKCE
    options.ProviderOptions.DefaultScopes.Add("openid");
    options.ProviderOptions.DefaultScopes.Add("profile");
    options.ProviderOptions.DefaultScopes.Add("email");
    options.ProviderOptions.DefaultScopes.Add("roles");
    options.ProviderOptions.DefaultScopes.Add("api");
    options.ProviderOptions.DefaultScopes.Add("offline_access"); // Refresh tokens

    // Maps OIDC roles claim → .NET role claim
    options.UserOptions.RoleClaim = "role";
});

// ─── HTTP Client ──────────────────────────────────────────────────────────────

// Authenticated HTTP client for the API
builder.Services.AddHttpClient("AuthAPI",
    client => client.BaseAddress = new Uri(
        builder.Configuration["ApiBaseUrl"] ?? "https://localhost:7100"))
    .AddHttpMessageHandler<BaseAddressAuthorizationMessageHandler>();

// Named scoped service to inject the client
builder.Services.AddScoped(sp => sp.GetRequiredService<IHttpClientFactory>().CreateClient("AuthAPI"));

// ─── App Services ─────────────────────────────────────────────────────────────

builder.Services.AddScoped<IAdminApiService, AdminApiService>();
builder.Services.AddScoped<IAccountApiService, AccountApiService>();

await builder.Build().RunAsync();
