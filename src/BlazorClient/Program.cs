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

var apiBaseUrl = builder.Configuration["ApiBaseUrl"] ?? "https://localhost:7100";

// Authenticated client — attaches the stored JWT to every request
builder.Services.AddHttpClient("AuthAPI",
    client => client.BaseAddress = new Uri(apiBaseUrl))
    .AddHttpMessageHandler<JwtTokenHandler>();

// Unauthenticated client — used for login before a token exists
builder.Services.AddHttpClient("Public", client => client.BaseAddress = new Uri(apiBaseUrl));

// Default injected HttpClient uses the authenticated named client
builder.Services.AddScoped(sp => sp.GetRequiredService<IHttpClientFactory>().CreateClient("AuthAPI"));

// ─── App Services ─────────────────────────────────────────────────────────────

builder.Services.AddScoped<IAdminApiService, AdminApiService>();
builder.Services.AddScoped<IAccountApiService, AccountApiService>();

await builder.Build().RunAsync();
