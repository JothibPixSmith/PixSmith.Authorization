using PixSmith.Authorization.BlazorClient;
using PixSmith.Authorization.BlazorClient.Services;
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

// Use the configured API authority so this works whether the WASM is hosted by
// the API server (same origin) or running standalone on a different port.
var apiBase = builder.Configuration["Auth:Authority"] is string authority
    ? authority.TrimEnd('/') + "/"
    : builder.HostEnvironment.BaseAddress;

builder.Services.AddHttpClient("AuthAPI",
    client => client.BaseAddress = new Uri(apiBase))
    .AddHttpMessageHandler<JwtTokenHandler>();

builder.Services.AddScoped(sp =>
    sp.GetRequiredService<IHttpClientFactory>().CreateClient("AuthAPI"));

// ─── App Services ─────────────────────────────────────────────────────────────

builder.Services.AddScoped<IAdminApiService, AdminApiService>();
builder.Services.AddScoped<IAccountApiService, AccountApiService>();

await builder.Build().RunAsync();
