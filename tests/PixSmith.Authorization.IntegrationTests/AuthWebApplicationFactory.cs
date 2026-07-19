using System.Linq;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using PixSmith.Authorization.DataContext;

namespace PixSmith.Authorization.IntegrationTests;

/// <summary>
/// Boots the real API host (controllers, Identity, OpenIddict, seeders) against a private
/// SQLite in-memory database instead of the dev "auth.db" file, so tests don't touch or
/// depend on local developer state and each test run starts from a clean schema.
/// </summary>
public sealed class AuthWebApplicationFactory : WebApplicationFactory<Program>
{
    private readonly SqliteConnection connection = new("DataSource=:memory:");

    public AuthWebApplicationFactory() => connection.Open();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // "Testing" (not "Development") so OpenIddict uses ephemeral signing/encryption
        // keys instead of dev certs backed by the machine's X.509 certificate store.
        builder.UseEnvironment("Testing");

        builder.ConfigureServices(services =>
        {
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
