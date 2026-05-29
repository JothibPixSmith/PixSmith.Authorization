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

// "AuthAPI" — all regular API calls; JwtTokenHandler proactively refreshes tokens.
builder.Services.AddHttpClient("AuthAPI",
    client => client.BaseAddress = new Uri(builder.HostEnvironment.BaseAddress))
    .AddHttpMessageHandler<JwtTokenHandler>();

// "NoAuth" — used only for /connect/token requests (login & refresh) to avoid the
// handler calling RefreshAsync while a refresh is already in flight.
builder.Services.AddHttpClient("NoAuth",
    client => client.BaseAddress = new Uri(builder.HostEnvironment.BaseAddress));

builder.Services.AddScoped(sp =>
    sp.GetRequiredService<IHttpClientFactory>().CreateClient("AuthAPI"));

// ─── App Services ─────────────────────────────────────────────────────────────

builder.Services.AddScoped<IAdminApiService, AdminApiService>();
builder.Services.AddScoped<IAccountApiService, AccountApiService>();
builder.Services.AddScoped<ITenantApiService, TenantApiService>();
builder.Services.AddScoped<IOidcAppApiService, OidcAppApiService>();

await builder.Build().RunAsync();
