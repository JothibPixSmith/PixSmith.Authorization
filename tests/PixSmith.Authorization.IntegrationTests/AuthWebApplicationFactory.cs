using System.Linq;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PixSmith.Authorization.DataContext;

namespace PixSmith.Authorization.IntegrationTests;

/// <summary>
/// Boots the real API host (controllers, Identity, OpenIddict, seeders) against a private
/// SQLite in-memory database instead of the dev "auth.db" file, so tests don't touch or
/// depend on local developer state and each test run starts from a clean schema.
/// </summary>
// Not sealed: RateLimitingTests derives a variant with a tighter limiter, so the override
// stays scoped to that host instead of mutating process-wide state.
public class AuthWebApplicationFactory : WebApplicationFactory<Program>
{
    private readonly SqliteConnection connection = new("DataSource=:memory:");

    public AuthWebApplicationFactory()
    {
        connection.Open();

        // The M2M client secret is no longer in appsettings.json — a secret committed to the
        // repository is a known secret — so the test host supplies a throwaway one.
        // An environment variable rather than UseSetting/ConfigureAppConfiguration: those are
        // layered under the application's own configuration sources under minimal hosting and
        // are not visible to the startup seeders that read IConfiguration directly.
        Environment.SetEnvironmentVariable(
            "OpenIddict__M2MClient__ClientSecret", "integration-tests-only-not-a-real-secret");

    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // "Testing" (not "Development") so OpenIddict uses ephemeral signing/encryption
        // keys instead of dev certs backed by the machine's X.509 certificate store.
        builder.UseEnvironment("Testing");

        builder.ConfigureServices(services =>
        {
            // The suite drives the credential endpoints far harder than a human would, and
            // every request shares one loopback partition. Raised rather than disabled, so the
            // limiter middleware still runs in every test; RateLimitingTests pins the real
            // behaviour with a limit of its own.
            services.Configure<PixSmith.Authorization.API.Security.RateLimitingOptions>(
                o => o.Auth.PermitLimit = 100_000);

            var descriptor = services.SingleOrDefault(
                d => d.ServiceType == typeof(DbContextOptions<ApplicationDbContext>));
            if (descriptor is not null) services.Remove(descriptor);

            services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseSqlite(connection, sqlite =>
                    sqlite.MigrationsAssembly("PixSmith.Authorization.DataContext.Migrations.Sqlite"));
                options.UseOpenIddict<Guid>();
            });
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing) connection.Dispose();
    }
}
