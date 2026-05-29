using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace PixSmith.Authorization.DataContext;

/// <summary>
/// Main EF Core DbContext. Uses ASP.NET Identity tables for auth and OpenIddict
/// tables for token/application management, with our custom domain entities alongside.
/// </summary>
public sealed class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
    : IdentityDbContext<IdentityUser<Guid>, IdentityRole<Guid>, Guid>(options)
{
    // Our domain entities stored as "shadow" tables - separate from Identity
    public DbSet<UserProfile> UserProfiles => Set<UserProfile>();
    public DbSet<OAuthClientRegistration> OAuthClientRegistrations => Set<OAuthClientRegistration>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
    public DbSet<TenantRecord> Tenants => Set<TenantRecord>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Rename Identity tables for clarity
        builder.Entity<IdentityUser<Guid>>().ToTable("Users");
        builder.Entity<IdentityRole<Guid>>().ToTable("Roles");
        builder.Entity<IdentityUserRole<Guid>>().ToTable("UserRoles");
        builder.Entity<IdentityUserClaim<Guid>>().ToTable("UserClaims");
        builder.Entity<IdentityUserLogin<Guid>>().ToTable("UserLogins");
        builder.Entity<IdentityUserToken<Guid>>().ToTable("UserTokens");
        builder.Entity<IdentityRoleClaim<Guid>>().ToTable("RoleClaims");

        builder.Entity<UserProfile>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.UserId).IsRequired();
            e.Property(x => x.FirstName).HasMaxLength(100);
            e.Property(x => x.LastName).HasMaxLength(100);
            e.HasIndex(x => x.UserId).IsUnique();
        });

        builder.Entity<OAuthClientRegistration>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.ClientId).HasMaxLength(100).IsRequired();
            e.Property(x => x.ClientSecret).HasMaxLength(500).IsRequired();
            e.Property(x => x.DisplayName).HasMaxLength(200).IsRequired();
            e.Property(x => x.ClientType).HasMaxLength(50).IsRequired();
            e.HasIndex(x => x.ClientId).IsUnique();
        });

        builder.Entity<AuditLog>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Action).HasMaxLength(200).IsRequired();
            e.HasIndex(x => x.UserId);
            e.HasIndex(x => x.OccurredAt);
        });

        builder.Entity<TenantRecord>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(200).IsRequired();
            e.Property(x => x.Slug).HasMaxLength(100).IsRequired();
            e.Property(x => x.Description).HasMaxLength(1000);
            e.HasIndex(x => x.Slug).IsUnique();
        });

        // Apply OpenIddict entity configurations
        builder.UseOpenIddict<Guid>();
    }
}

// ─── EF entities that shadow our Domain entities ───────────────────────────

public class UserProfile
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? PhoneNumber { get; set; }
    public string? ProfilePictureUrl { get; set; }
    public bool IsActive { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? LastLoginAt { get; set; }
}

public class OAuthClientRegistration
{
    public Guid Id { get; set; }
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string? LogoUri { get; set; }
    public string ClientType { get; set; } = "Confidential";
    public bool IsActive { get; set; } = true;
    public bool RequireConsent { get; set; }
    public bool RequirePkce { get; set; }
    public bool AllowOfflineAccess { get; set; } = true;
    public int AccessTokenLifetimeSeconds { get; set; } = 3600;
    public int IdentityTokenLifetimeSeconds { get; set; } = 300;
    public int? AbsoluteRefreshTokenLifetimeSeconds { get; set; }
    public string RedirectUrisJson { get; set; } = "[]";
    public string AllowedScopesJson { get; set; } = "[]";
    public string AllowedGrantTypesJson { get; set; } = "[]";
    public string CorsOriginsJson { get; set; } = "[]";
    public Guid CreatedByUserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

public class AuditLog
{
    public Guid Id { get; set; }
    public Guid? UserId { get; set; }
    public string Action { get; set; } = string.Empty;
    public string? Details { get; set; }
    public string? IpAddress { get; set; }
    public DateTimeOffset OccurredAt { get; set; }
}

public class TenantRecord
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Slug { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsActive { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; }
}
