using BlazorClient;
using BlazorClient.Services;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

// ─── Authentication ───────────────────────────────────────────────────────────

builder.Services.AddAuthorizationCore();
builder.Services.AddScoped<JwtAuthStateProvider>();
builder.Services.AddScoped<AuthenticationStateProvider>(
    sp => sp.GetRequiredService<JwtAuthStateProvider>());
builder.Services.AddScoped<JwtTokenHandler>();

// ─── HTTP Clients ─────────────────────────────────────────────────────────────

var authApiBaseUrl = builder.Configuration["AuthApiBaseUrl"] ?? "https://localhost:7100";

// All API calls go directly to the AuthServer. The JwtTokenHandler attaches the
// encrypted access token as a Bearer header on every request.
builder.Services.AddHttpClient("AuthAPI",
    client => client.BaseAddress = new Uri(authApiBaseUrl.TrimEnd('/') + "/"))
    .AddHttpMessageHandler<JwtTokenHandler>();

builder.Services.AddScoped(sp =>
    sp.GetRequiredService<IHttpClientFactory>().CreateClient("AuthAPI"));

// ─── App Services ─────────────────────────────────────────────────────────────

builder.Services.AddScoped<IAdminApiService, AdminApiService>();
builder.Services.AddScoped<IAccountApiService, AccountApiService>();

await builder.Build().RunAsync();
