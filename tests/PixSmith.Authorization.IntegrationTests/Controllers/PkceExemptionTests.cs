using System.Net;
using FluentAssertions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Infrastructure.OpenIddict;
using PixSmith.Authorization.Services.Interfaces;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PixSmith.Authorization.IntegrationTests.Controllers;

/// <summary>
/// PKCE is enforced per client, with one gated exception for conformance-test clients.
///
/// <para>
/// The server-wide switch was removed so a single test client could be exempt. That makes
/// every other client's PKCE depend on its own requirement being present, so these tests pin
/// each route by which a client could end up without it: created through the admin service,
/// edited, left over from before (the startup backfill), or exempted while the gate is off.
/// </para>
/// </summary>
public sealed class PkceExemptionTests : IDisposable
{
    private const string RedirectUri = "https://client.test/callback";
    private const string S256Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private readonly SecurityWebApplicationFactory _factory = new();

    public void Dispose() => _factory.Dispose();

    // ── Every authorization-code client gets PKCE ─────────────────────────────

    [Fact]
    public async Task A_confidential_code_client_requires_PKCE()
    {
        // The old rule required PKCE for public clients only. This is the case it missed.
        var created = await CreateAsync(_factory, "confidential-app", confidential: true);
        created.IsSuccess.Should().BeTrue(created.Error);
        created.Value!.Requirements.Should().Contain(Requirements.Features.ProofKeyForCodeExchange);
        created.Value.PkceExempt.Should().BeFalse();

        var response = await AuthorizeAsync(_factory, "confidential-app");

        AssertRefused(response);
    }

    [Fact]
    public async Task S256_still_reaches_the_login_page()
    {
        await CreateAsync(_factory, "confidential-app", confidential: true);

        var response = await AuthorizeAsync(_factory, "confidential-app",
            ("code_challenge", S256Challenge), ("code_challenge_method", "S256"));

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        response.Headers.Location!.ToString().Should().Contain("/Account/Login");
    }

    // ── The exemption gate ────────────────────────────────────────────────────

    [Fact]
    public async Task An_exemption_is_refused_while_the_setting_is_off()
    {
        var result = await CreateAsync(_factory, "oidf-conformance", confidential: true, exempt: true);

        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Contain(PkcePolicy.AllowExemptClientsKey);
    }

    [Fact]
    public async Task With_the_setting_on_an_exempt_client_may_omit_PKCE_but_not_use_plain()
    {
        using var allowing = Allowing(_factory);
        var created = await CreateAsync(allowing, "oidf-conformance", confidential: true, exempt: true);
        created.IsSuccess.Should().BeTrue(created.Error);
        created.Value!.PkceExempt.Should().BeTrue();

        var withoutPkce = await AuthorizeAsync(allowing, "oidf-conformance");
        withoutPkce.StatusCode.Should().Be(HttpStatusCode.Redirect);
        withoutPkce.Headers.Location!.ToString().Should().Contain("/Account/Login");

        // Exempt from having to send PKCE, never allowed a weak one.
        var plain = await AuthorizeAsync(allowing, "oidf-conformance",
            ("code_challenge", "a-verifier-sent-in-the-clear-0123456789abcdef"), ("code_challenge_method", "plain"));
        AssertRefused(plain);
    }

    [Fact]
    public async Task With_the_setting_on_other_clients_still_require_PKCE()
    {
        using var allowing = Allowing(_factory);
        await CreateAsync(allowing, "oidf-conformance", confidential: true, exempt: true);
        await CreateAsync(allowing, "ordinary-app", confidential: true);

        AssertRefused(await AuthorizeAsync(allowing, "ordinary-app"));
    }

    [Theory]
    [InlineData(false, "authorization_code", "confidential client")]
    [InlineData(true, "client_credentials", "authorization_code grant")]
    public async Task An_exemption_is_refused_where_it_makes_no_sense(bool confidential, string grant, string reason)
    {
        using var allowing = Allowing(_factory);

        var result = await CreateAsync(allowing, "oidf-conformance", confidential, exempt: true, grant);

        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Contain(reason);
    }

    [Fact]
    public async Task Editing_an_exempt_client_without_the_flag_restores_PKCE()
    {
        using var allowing = Allowing(_factory);
        await CreateAsync(allowing, "oidf-conformance", confidential: true, exempt: true);

        using var scope = allowing.Services.CreateScope();
        var apps = scope.ServiceProvider.GetRequiredService<IOidcAppService>();
        var updated = await apps.UpdateAsync("oidf-conformance", new UpdateOidcAppRequest(
            "renamed", [RedirectUri], [], ["openid"], ["authorization_code"]));
        updated.IsSuccess.Should().BeTrue(updated.Error);

        (await apps.GetByClientIdAsync("oidf-conformance")).Value!.PkceExempt.Should().BeFalse();
        AssertRefused(await AuthorizeAsync(allowing, "oidf-conformance"));
    }

    // ── The startup backfill ──────────────────────────────────────────────────

    [Fact]
    public async Task Backfill_adds_PKCE_to_a_code_client_that_lacks_it()
    {
        using var scope = _factory.Services.CreateScope();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        await manager.CreateAsync(LegacyDescriptor("legacy-app"));

        var changed = await PkcePolicy.EnforceAsync(manager, exemptionsAllowed: false);

        changed.Should().Equal("legacy-app");
        var app = await manager.FindByClientIdAsync("legacy-app");
        (await manager.GetRequirementsAsync(app!)).Should().Contain(Requirements.Features.ProofKeyForCodeExchange);
        AssertRefused(await AuthorizeAsync(_factory, "legacy-app"));

        // Idempotent: a second pass changes nothing.
        (await PkcePolicy.EnforceAsync(manager, exemptionsAllowed: false)).Should().BeEmpty();
    }

    [Fact]
    public async Task Backfill_keeps_a_flagged_client_exempt_only_while_exemptions_are_allowed()
    {
        using var scope = _factory.Services.CreateScope();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var flagged = LegacyDescriptor("oidf-conformance");
        flagged.Settings[PkcePolicy.ExemptSetting] = "true";
        await manager.CreateAsync(flagged);

        (await PkcePolicy.EnforceAsync(manager, exemptionsAllowed: true)).Should().BeEmpty();

        // The setting is switched off and the server restarted: the flag is now ignored.
        (await PkcePolicy.EnforceAsync(manager, exemptionsAllowed: false)).Should().Equal("oidf-conformance");
    }

    [Fact]
    public async Task Backfill_leaves_clients_without_the_code_grant_alone()
    {
        using var scope = _factory.Services.CreateScope();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        // The seeded m2m client (client_credentials) and blazor-client (already has PKCE).
        (await PkcePolicy.EnforceAsync(manager, exemptionsAllowed: false)).Should().BeEmpty();
    }

    // ── Never in production ───────────────────────────────────────────────────

    [Theory]
    [InlineData("Production", true)]
    [InlineData("Staging", false)]
    [InlineData("Development", false)]
    public void Exemptions_cannot_be_switched_on_in_production(string environment, bool throws)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { [PkcePolicy.AllowExemptClientsKey] = "true" })
            .Build();

        var act = () => PkcePolicy.ValidateConfiguration(configuration, new FakeEnvironment(environment));

        if (throws) act.Should().Throw<InvalidOperationException>().WithMessage("*Production*");
        else act.Should().NotThrow();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static WebApplicationFactory<Program> Allowing(SecurityWebApplicationFactory factory) =>
        factory.WithWebHostBuilder(builder => builder.UseSetting(PkcePolicy.AllowExemptClientsKey, "true"));

    private static async Task<PixSmith.Authorization.Domain.Results.Result<OidcAppDto>> CreateAsync(
        WebApplicationFactory<Program> factory, string clientId, bool confidential,
        bool exempt = false, string grant = "authorization_code")
    {
        using var scope = factory.Services.CreateScope();
        var apps = scope.ServiceProvider.GetRequiredService<IOidcAppService>();
        return await apps.CreateAsync(new CreateOidcAppRequest(
            clientId,
            confidential ? "a-test-secret-0123456789" : null,
            clientId,
            confidential ? ClientTypes.Confidential : ClientTypes.Public,
            grant == "authorization_code" ? [RedirectUri] : [],
            [],
            ["openid"],
            [grant],
            PkceExempt: exempt));
    }

    /// <summary>A code client as it might exist from before PKCE was required per client.</summary>
    private static OpenIddictApplicationDescriptor LegacyDescriptor(string clientId) => new()
    {
        ClientId = clientId,
        ClientSecret = "a-test-secret-0123456789",
        ClientType = ClientTypes.Confidential,
        RedirectUris = { new Uri(RedirectUri) },
        Permissions =
        {
            Permissions.Endpoints.Authorization,
            Permissions.Endpoints.Token,
            Permissions.GrantTypes.AuthorizationCode,
            Permissions.ResponseTypes.Code,
            Permissions.Prefixes.Scope + Scopes.OpenId,
        },
    };

    private static async Task<HttpResponseMessage> AuthorizeAsync(
        WebApplicationFactory<Program> factory, string clientId, params (string Key, string Value)[] pkce)
    {
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost/"),
            AllowAutoRedirect = false,
        });

        var query = new Dictionary<string, string>
        {
            ["client_id"] = clientId,
            ["redirect_uri"] = RedirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid",
            ["state"] = "state-123",
        };
        foreach (var (key, value) in pkce) query[key] = value;

        return await client.GetAsync("/connect/authorize?" + string.Join("&",
            query.Select(p => $"{p.Key}={Uri.EscapeDataString(p.Value)}")));
    }

    /// <summary>Refused before sign-in: an error page, or an error redirect to the client.</summary>
    private static void AssertRefused(HttpResponseMessage response)
    {
        var location = response.Headers.Location?.ToString() ?? "";
        location.Should().NotContain("/Account/Login", "the request must be refused before sign-in");

        if (response.StatusCode == HttpStatusCode.Redirect)
            location.Should().StartWith(RedirectUri).And.Contain("error=");
        else
            response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    private sealed class FakeEnvironment(string name) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = name;
        public string ApplicationName { get; set; } = "PixSmith.Authorization.API";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
