using System.Text.Json;
using System.Text;
using System.Net.Http.Json;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Services;
using PixSmith.Authorization.Domain.Entities;
using PixSmith.Authorization.Repositories.Interfaces;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PixSmith.Authorization.IntegrationTests;

/// <summary>
/// Boots the real host for testing the security-critical paths over HTTP: tenancy
/// enforcement, the admin policy, and signed tenant provisioning.
///
/// <para>
/// These checks live at the seam between the controllers and the services. The unit suite
/// proves each policy correct in isolation, which says nothing about whether the endpoints
/// actually consult it — a refactor could drop the check and leave every unit test passing.
/// </para>
///
/// <para>
/// Runs as "Testing", not "Development", so OpenIddict keeps its transport-security
/// requirement exactly as production does; the client therefore uses an https base address.
/// Two provisioning keys are generated per factory instance so the signature quorum is
/// exercised with real ECDSA signatures rather than a stub.
/// </para>
/// </summary>
public sealed class SecurityWebApplicationFactory : WebApplicationFactory<Program>
{
    private readonly SqliteConnection _connection = new("DataSource=:memory:");

    public const string AdminEmail = "admin@test.local";
    public const string AdminPassword = "Admin1234!";
    public const string UserPassword = "User1234!";

    /// <summary>Provisioning signing keys. Private halves never leave the test process.</summary>
    public ECDsa KeyA { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public ECDsa KeyB { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public const string KeyAId = "test-key-a";
    public const string KeyBId = "test-key-b";

    public SecurityWebApplicationFactory()
    {
        TestSecrets.Ensure();
        _connection.Open();
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");

        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                // Seeds an administrator holding the platform Admin role.
                ["AdminSeed:Email"] = AdminEmail,
                ["AdminSeed:Username"] = "admin",
                ["AdminSeed:Password"] = AdminPassword,

                // The admin UI administers the server itself and is exempt from tenancy.
                ["TenantEnforcement:PlatformClients:0"] = "blazor-client",

                // A real two-of-two quorum.
                ["TenantProvisioning:RequiredSignatures"] = "2",
                ["TenantProvisioning:Keys:0:KeyId"] = KeyAId,
                ["TenantProvisioning:Keys:0:Holder"] = "Test Key A",
                ["TenantProvisioning:Keys:0:PublicKey"] = Convert.ToBase64String(KeyA.ExportSubjectPublicKeyInfo()),
                ["TenantProvisioning:Keys:1:KeyId"] = KeyBId,
                ["TenantProvisioning:Keys:1:Holder"] = "Test Key B",
                ["TenantProvisioning:Keys:1:PublicKey"] = Convert.ToBase64String(KeyB.ExportSubjectPublicKeyInfo()),

                // The backfill would otherwise sweep every seeded user into a default
                // tenancy and mask exactly what these tests are checking.
                ["TenantBackfill:TenantName"] = "Backfill (unused)",
            });
        });

        builder.ConfigureServices(services =>
        {
            var descriptor = services.SingleOrDefault(
                d => d.ServiceType == typeof(DbContextOptions<ApplicationDbContext>));
            if (descriptor is not null) services.Remove(descriptor);

            services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseSqlite(_connection, sqlite =>
                    sqlite.MigrationsAssembly("PixSmith.Authorization.DataContext.Migrations.Sqlite"));
                options.UseOpenIddict<Guid>();
            });
        });
    }

    /// <summary>https, because the host enforces transport security outside Development.</summary>
    public HttpClient CreateApiClient() => CreateClient(new WebApplicationFactoryClientOptions
    {
        BaseAddress = new Uri("https://localhost/"),
        AllowAutoRedirect = false,
    });

    // ── Seeding, done through the real services rather than raw SQL ───────────

    public async Task<Guid> CreateUserAsync(string userName, string? platformRole = null)
    {
        using var scope = Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser<Guid>>>();

        var user = new IdentityUser<Guid>
        {
            Id = Guid.NewGuid(),
            UserName = userName,
            Email = $"{userName}@test.local",
            EmailConfirmed = true,   // SignIn.RequireConfirmedEmail is on
        };

        var result = await users.CreateAsync(user, UserPassword);
        if (!result.Succeeded)
            throw new InvalidOperationException(string.Join("; ", result.Errors.Select(e => e.Description)));

        if (platformRole is not null)
            await users.AddToRoleAsync(user, platformRole);

        return user.Id;
    }

    public async Task<Guid> CreateTenantAsync(string name)
    {
        using var scope = Services.CreateScope();
        var tenants = scope.ServiceProvider.GetRequiredService<ITenantRepository>();

        var tenant = Tenant.Create(name, null);
        await tenants.AddAsync(tenant);
        return tenant.Id;
    }

    public async Task AddMemberAsync(
        Guid tenantId, Guid userId, string[] roles, string? denyClientId = null)
    {
        using var scope = Services.CreateScope();
        var memberships = scope.ServiceProvider.GetRequiredService<ITenantMembershipRepository>();

        var membership = TenantMembership.Create(tenantId, userId, roles);
        if (denyClientId is not null) membership.DenyApplication(denyClientId, "denied by test");

        await memberships.AddAsync(membership);
    }

    public async Task DeactivateTenantAsync(Guid tenantId)
    {
        using var scope = Services.CreateScope();
        var tenants = scope.ServiceProvider.GetRequiredService<ITenantRepository>();

        var tenant = await tenants.GetByIdAsync(tenantId)
            ?? throw new InvalidOperationException("Tenant not found.");

        tenant.Deactivate();
        await tenants.UpdateAsync(tenant);
    }

    public async Task SubscribeAsync(Guid tenantId, string clientId)
    {
        using var scope = Services.CreateScope();
        var subscriptions = scope.ServiceProvider.GetRequiredService<ITenantApplicationRepository>();
        await subscriptions.AddAsync(TenantApplication.Create(tenantId, clientId));
    }

    public async Task RegisterClientAsync(
        string clientId, string[] grantTypes, string[] scopes,
        string? clientSecret = null, bool confidential = false)
    {
        using var scope = Services.CreateScope();
        var apps = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
            DisplayName = clientId,
            ClientType = confidential ? ClientTypes.Confidential : ClientTypes.Public,
            Permissions = { Permissions.Endpoints.Token },
        };

        foreach (var grant in grantTypes)
            descriptor.Permissions.Add(Permissions.Prefixes.GrantType + grant);

        if (grantTypes.Contains("authorization_code"))
        {
            descriptor.Permissions.Add(Permissions.Endpoints.Authorization);
            descriptor.Permissions.Add(Permissions.ResponseTypes.Code);
            descriptor.RedirectUris.Add(new Uri($"{RedirectBase}/{clientId}"));

            // PkcePolicy backfills this at startup; a client registered mid-test misses that
            // pass, so require it here rather than silently testing a weaker client than
            // production would ever have.
            descriptor.Requirements.Add(Requirements.Features.ProofKeyForCodeExchange);
        }
        foreach (var s in scopes)
            descriptor.Permissions.Add(Permissions.Prefixes.Scope + s);

        await apps.CreateAsync(descriptor);
    }

    /// <summary>
    /// Creates a client through <c>IOidcAppService</c> — the same path the admin API uses —
    /// so its validation is exercised. <c>RegisterClientAsync</c> goes straight to the
    /// OpenIddict manager and deliberately bypasses it.
    /// </summary>
    public async Task<(bool Succeeded, string Error)> CreateOidcAppAsync(
        string clientId, string[] grantTypes, string[] scopes, bool confidential = false,
        bool allowIntrospection = false)
    {
        using var scope = Services.CreateScope();
        var apps = scope.ServiceProvider
            .GetRequiredService<Services.Interfaces.IOidcAppService>();

        var result = await apps.CreateAsync(new DataContext.CreateOidcAppRequest(
            ClientId: clientId,
            ClientSecret: confidential ? "secret-for-tests" : null,
            DisplayName: clientId,
            ClientType: confidential ? ClientTypes.Confidential : ClientTypes.Public,
            RedirectUris: [],
            PostLogoutRedirectUris: [],
            Scopes: [.. scopes],
            GrantTypes: [.. grantTypes],
            PkceExempt: false,
            AllowIntrospection: allowIntrospection));

        return (result.IsSuccess, result.Error ?? string.Empty);
    }

    /// <summary>
    /// The client's registered permission strings. Endpoint permissions are the subject of
    /// CR-7: a grant with no matching <c>ept:…</c> permission is refused at the endpoint, so
    /// the two have to be asserted separately.
    /// </summary>
    public async Task<IReadOnlyList<string>> GetClientPermissionsAsync(string clientId)
    {
        using var scope = Services.CreateScope();
        var apps = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        var app = await apps.FindByClientIdAsync(clientId)
            ?? throw new InvalidOperationException($"no client '{clientId}'.");

        return [.. await apps.GetPermissionsAsync(app)];
    }

    /// <summary>Null when no client with that id exists.</summary>
    public async Task<object?> FindClientAsync(string clientId)
    {
        using var scope = Services.CreateScope();
        var apps = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        return await apps.FindByClientIdAsync(clientId);
    }

    public const string RedirectBase = "https://test.local/callback";

    /// <summary>
    /// Obtains a user access token the way a real client does: sign in at the server's login
    /// page, then authorization code + PKCE.
    ///
    /// <para>
    /// These tests used to post the password grant, which was removed — the admin UI and the
    /// provisioning scripts were its only users, and advertising it was a pen-test finding.
    /// Driving the real redirect flow here means the tests exercise the same path browsers
    /// take, including the tenancy decision made at the authorization endpoint.
    /// </para>
    /// </summary>
    /// <summary>The outcome of a full authorization-code exchange, including a refusal.</summary>
    public sealed record TokenOutcome(
        string? AccessToken, string? Error, string? ErrorDescription)
    {
        public bool Succeeded => AccessToken is not null;
    }

    /// <summary>
    /// Makes sure the client will accept the test callback. Seeded clients (blazor-client)
    /// register their real redirect URIs, and OpenIddict rejects any other, so the test URI
    /// has to be added rather than assumed.
    /// </summary>
    private async Task EnsureRedirectUriAsync(string clientId)
    {
        using var scope = Services.CreateScope();
        var apps = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        var app = await apps.FindByClientIdAsync(clientId);
        if (app is null) return;

        var expected = new Uri($"{RedirectBase}/{clientId}");
        var existing = await apps.GetRedirectUrisAsync(app);
        if (existing.Contains(expected.AbsoluteUri)) return;

        var descriptor = new OpenIddictApplicationDescriptor();
        await apps.PopulateAsync(descriptor, app);
        descriptor.RedirectUris.Add(expected);

        // The authorization endpoint must be permitted for the redirect to mean anything.
        descriptor.Permissions.Add(Permissions.Endpoints.Authorization);
        descriptor.Permissions.Add(Permissions.ResponseTypes.Code);
        descriptor.Permissions.Add(Permissions.Prefixes.GrantType + "authorization_code");

        await apps.UpdateAsync(app, descriptor);
    }

    /// <summary>
    /// Like <see cref="GetUserTokenAsync"/> but returns a refusal instead of throwing, for
    /// the tests that assert access is denied. A tenancy denial now surfaces as
    /// <c>error=access_denied</c> on the authorization redirect rather than as a failed token
    /// request, because the decision is made at the authorization endpoint.
    /// </summary>
    public async Task<TokenOutcome> TryGetUserTokenAsync(
        string clientId, string email, string scope, string? organization = null)
    {
        try
        {
            return new TokenOutcome(
                await GetUserTokenAsync(clientId, email, scope, organization), null, null);
        }
        catch (AuthorizationRefusedException refused)
        {
            return new TokenOutcome(null, refused.Error, refused.ErrorDescription);
        }
    }

    public sealed class AuthorizationRefusedException(string? error, string? description)
        : Exception($"authorization refused: {error} — {description}")
    {
        public string? Error { get; } = error;
        public string? ErrorDescription { get; } = description;
    }

    public async Task<string> GetUserTokenAsync(
        string clientId, string email, string scope, string? organization = null) =>
        (await GetUserTokensAsync(clientId, email, scope, organization)).AccessToken!;

    /// <summary>Both tokens from one exchange, for the tests that need the refresh token.</summary>
    public sealed record TokenPair(string? AccessToken, string? RefreshToken);

    /// <summary>
    /// The full exchange. <see cref="GetUserTokenAsync"/> is the common case; this exists
    /// because revocation can only be observed through the refresh token — an access token is
    /// a self-contained JWT and keeps validating until it expires either way.
    /// </summary>
    public async Task<TokenPair> GetUserTokensAsync(
        string clientId, string email, string scope, string? organization = null)
    {
        await EnsureRedirectUriAsync(clientId);

        // https, for the same reason CreateApiClient uses it: the host enforces transport
        // security outside Development, and the protocol endpoints refuse plain HTTP.
        var client = CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost/"),
            AllowAutoRedirect = false,
            HandleCookies = true,
        });

        // ── Sign in (sets the shared Identity cookie) ────────────────────────
        var form = await client.GetAsync("/Account/Login");
        form.EnsureSuccessStatusCode();
        var html = await form.Content.ReadAsStringAsync();
        var antiforgery = System.Text.RegularExpressions.Regex.Match(
            html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;

        var password = email.StartsWith("admin", StringComparison.OrdinalIgnoreCase)
            ? AdminPassword
            : UserPassword;

        var login = await client.PostAsync("/Account/Login", new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("Email", email),
            new("Password", password),
            new("__RequestVerificationToken", antiforgery),
        ]));

        if (login.StatusCode != System.Net.HttpStatusCode.Found)
        {
            throw new InvalidOperationException(
                $"sign-in for {email} did not redirect (got {(int)login.StatusCode}); "
                + "the credentials or the login page changed.");
        }

        // ── Authorization request ────────────────────────────────────────────
        var verifier = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var challenge = Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var redirectUri = $"{RedirectBase}/{clientId}";
        var authorize = $"/connect/authorize?client_id={Uri.EscapeDataString(clientId)}"
            + "&response_type=code"
            + $"&redirect_uri={Uri.EscapeDataString(redirectUri)}"
            + $"&scope={Uri.EscapeDataString(scope)}"
            + $"&code_challenge={challenge}&code_challenge_method=S256&state=test"
            + (organization is null ? "" : $"&organization={Uri.EscapeDataString(organization)}");

        var authorized = await client.GetAsync(authorize);

        if (authorized.StatusCode != System.Net.HttpStatusCode.Found)
        {
            throw new InvalidOperationException(
                $"/connect/authorize returned {(int)authorized.StatusCode}, not a redirect. "
                + $"Body: {await authorized.Content.ReadAsStringAsync()}");
        }

        var location = authorized.Headers.Location
            ?? throw new InvalidOperationException("authorize redirect carried no Location.");

        var parameters = location.Query.TrimStart('?').Split('&')
            .Select(pair => pair.Split('=', 2))
            .Where(pair => pair.Length == 2)
            .ToDictionary(pair => pair[0], pair => Uri.UnescapeDataString(pair[1]));

        // A tenancy refusal comes back on the redirect, not as an exception.
        if (parameters.TryGetValue("error", out var error))
        {
            throw new AuthorizationRefusedException(
                error, parameters.GetValueOrDefault("error_description"));
        }

        var code = location.Query.TrimStart('?').Split('&')
            .Select(pair => pair.Split('=', 2))
            .Where(pair => pair.Length == 2 && pair[0] == "code")
            .Select(pair => Uri.UnescapeDataString(pair[1]))
            .FirstOrDefault()
            ?? throw new InvalidOperationException(
                $"authorize did not return a code: {location.Query}");

        // ── Redeem ───────────────────────────────────────────────────────────
        var token = await client.PostAsync("/connect/token", new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("grant_type", "authorization_code"),
            new("client_id", clientId),
            new("redirect_uri", redirectUri),
            new("code", code),
            new("code_verifier", verifier),
        ]));

        var body = await token.Content.ReadFromJsonAsync<JsonElement>();
        if (!token.IsSuccessStatusCode)
            throw new InvalidOperationException($"token exchange failed: {body}");

        return new TokenPair(
            body.GetProperty("access_token").GetString(),
            body.TryGetProperty("refresh_token", out var refresh) ? refresh.GetString() : null);
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (!disposing) return;

        _connection.Dispose();
        KeyA.Dispose();
        KeyB.Dispose();
    }
}
