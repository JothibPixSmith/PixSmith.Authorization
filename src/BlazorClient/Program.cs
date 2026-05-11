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
builder.Services.AddScoped<BffAuthStateProvider>();
builder.Services.AddScoped<AuthenticationStateProvider>(
    sp => sp.GetRequiredService<BffAuthStateProvider>());
builder.Services.AddScoped<IncludeCredentialsHandler>();

// ─── HTTP Clients ─────────────────────────────────────────────────────────────

var bffBaseUrl = builder.Configuration["BffBaseUrl"] ?? "https://localhost:7300";

// BFF-specific endpoints: /bff/login, /bff/logout, /bff/user
builder.Services.AddHttpClient("BffClient",
    client => client.BaseAddress = new Uri(bffBaseUrl))
    .AddHttpMessageHandler<IncludeCredentialsHandler>();

// All AuthServer API calls routed through the BFF proxy.
// Trailing slash is required so relative paths (e.g. "api/admin/...") resolve correctly.
builder.Services.AddHttpClient("AuthAPI",
    client => client.BaseAddress = new Uri($"{bffBaseUrl.TrimEnd('/')}/bff/proxy/"))
    .AddHttpMessageHandler<IncludeCredentialsHandler>();

// Default injected HttpClient uses the proxied API client
builder.Services.AddScoped(sp => sp.GetRequiredService<IHttpClientFactory>().CreateClient("AuthAPI"));

// ─── App Services ─────────────────────────────────────────────────────────────

builder.Services.AddScoped<IAdminApiService, AdminApiService>();
builder.Services.AddScoped<IAccountApiService, AccountApiService>();

await builder.Build().RunAsync();
