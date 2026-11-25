using PixSmith.Authorization.BlazorClient;
using PixSmith.Authorization.BlazorClient.Services;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Authentication;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

// ─── Authentication ───────────────────────────────────────────────────────────
//
// Authorization code + PKCE, via a redirect to the server's own login page.
//
// This replaced a password grant: the UI used to collect the password itself and POST it to
// /connect/token. That made the admin console a second place credentials were typed and
// handled, kept the password grant advertised in discovery, and could never support MFA or
// an external identity provider. Now the UI never sees a password at all.

builder.Services.AddOidcAuthentication(options =>
{
    var auth = builder.Configuration.GetSection("Auth");

    // The API hosts this client, so the authority is always this same origin. Resolved at
    // runtime rather than configured, so one build works on the debug stack, the staging
    // stack and production without a per-environment value to forget.
    options.ProviderOptions.Authority = builder.HostEnvironment.BaseAddress;
    options.ProviderOptions.ClientId = auth["ClientId"] ?? "blazor-client";

    // Code flow; the library adds PKCE itself, and the server requires it per client.
    options.ProviderOptions.ResponseType = "code";

    options.ProviderOptions.DefaultScopes.Clear();
    foreach (var scope in (auth["Scope"] ?? "openid profile").Split(' ',
                 StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
    {
        options.ProviderOptions.DefaultScopes.Add(scope);
    }

    // The tokens carry two distinct role claims: "role" holds the platform Identity roles
    // this UI authorizes on (AuthorizeView Roles="Admin"), while "roles" holds company
    // roles. Naming the wrong one would make every admin page look unauthorized.
    options.UserOptions.RoleClaim = "role";
    options.UserOptions.NameClaim = "name";
});

// ─── HTTP Clients ─────────────────────────────────────────────────────────────

// AuthorizationMessageHandler attaches the access token and renews it from the OIDC
// session, which is what replaced JwtTokenHandler's manual refresh against /connect/token.
builder.Services.AddScoped<ApiAuthorizationMessageHandler>();

builder.Services.AddHttpClient("AuthAPI",
    client => client.BaseAddress = new Uri(builder.HostEnvironment.BaseAddress))
    .AddHttpMessageHandler<ApiAuthorizationMessageHandler>();

// "NoAuth" — endpoints that must be reachable before sign-in, such as registration.
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
