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
    public DbSet<EmailOutboxMessage> EmailOutboxMessages => Set<EmailOutboxMessage>();
    public DbSet<ProvisioningNonce> ProvisioningNonces => Set<ProvisioningNonce>();

    // Multi-tenancy (docs/MULTI-TENANCY.md). Present but not yet read by the
    // authorization path — see that document's staging table.
    public DbSet<TenantMembershipRecord> TenantMemberships => Set<TenantMembershipRecord>();
    public DbSet<TenantMembershipRoleRecord> TenantMembershipRoles => Set<TenantMembershipRoleRecord>();
    public DbSet<MembershipApplicationRoleRecord> MembershipApplicationRoles => Set<MembershipApplicationRoleRecord>();
    public DbSet<TenantApplicationRecord> TenantApplications => Set<TenantApplicationRecord>();

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

        builder.Entity<EmailOutboxMessage>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.ToEmail).HasMaxLength(320).IsRequired();
            e.Property(x => x.Subject).HasMaxLength(300).IsRequired();
            e.Property(x => x.Body).IsRequired();
            e.Property(x => x.Status).HasMaxLength(20).IsRequired();
            e.Property(x => x.LastError).HasMaxLength(2000);
            e.HasIndex(x => new { x.Status, x.NextAttemptAt });
        });

        builder.Entity<ProvisioningNonce>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Nonce).HasMaxLength(128).IsRequired();
            e.Property(x => x.Operation).HasMaxLength(300).IsRequired();
            e.Property(x => x.SignedBy).HasMaxLength(500).IsRequired();
            // The uniqueness constraint *is* the replay defence — it must be enforced by
            // the database, not by a read-then-write check that two concurrent replays
            // could both pass.
            e.HasIndex(x => x.Nonce).IsUnique();
            e.HasIndex(x => x.UsedAt);
        });

        // ─── Multi-tenancy ──────────────────────────────────────────────────
        // Cascade deletes are declared explicitly: removing a company must not strand
        // membership or subscription rows that would otherwise keep granting access.

        builder.Entity<TenantMembershipRecord>(e =>
        {
            e.HasKey(x => x.Id);
            // One membership per person per company. The database enforces this rather
            // than application code, so a concurrent double-invite cannot create two.
            e.HasIndex(x => new { x.TenantId, x.UserId }).IsUnique();
            e.HasIndex(x => x.UserId);
            e.HasOne<TenantRecord>().WithMany()
                .HasForeignKey(x => x.TenantId).OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<TenantMembershipRoleRecord>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Role).HasMaxLength(100).IsRequired();
            e.HasIndex(x => new { x.MembershipId, x.Role }).IsUnique();
            e.HasOne<TenantMembershipRecord>().WithMany()
                .HasForeignKey(x => x.MembershipId).OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<MembershipApplicationRoleRecord>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.ClientId).HasMaxLength(100).IsRequired();
            e.Property(x => x.Role).HasMaxLength(100).IsRequired();
            e.HasIndex(x => new { x.MembershipId, x.ClientId, x.Role }).IsUnique();
            e.HasOne<TenantMembershipRecord>().WithMany()
                .HasForeignKey(x => x.MembershipId).OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<TenantApplicationRecord>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.ClientId).HasMaxLength(100).IsRequired();
            e.HasIndex(x => new { x.TenantId, x.ClientId }).IsUnique();
            e.HasIndex(x => x.ClientId);
            e.HasOne<TenantRecord>().WithMany()
                .HasForeignKey(x => x.TenantId).OnDelete(DeleteBehavior.Cascade);
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

/// <summary>
/// A single-use nonce consumed by a signed tenant-provisioning request. Rows are only
/// written once every signature has verified, so a failed attempt cannot burn a nonce.
/// </summary>
public class ProvisioningNonce
{
    public Guid Id { get; set; }
    public string Nonce { get; set; } = string.Empty;
    /// <summary>The HTTP method and path the nonce was spent on, e.g. "POST /api/admin/tenants".</summary>
    public string Operation { get; set; } = string.Empty;
    /// <summary>Comma-separated key IDs whose signatures satisfied the quorum.</summary>
    public string SignedBy { get; set; } = string.Empty;
    /// <summary>The human operator who submitted the request.</summary>
    public Guid? UserId { get; set; }
    public DateTimeOffset UsedAt { get; set; }
}

/// <summary>A person's membership of a company. See docs/MULTI-TENANCY.md.</summary>
public class TenantMembershipRecord
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public Guid UserId { get; set; }
    public bool IsActive { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>A role held across a whole company.</summary>
public class TenantMembershipRoleRecord
{
    public Guid Id { get; set; }
    public Guid MembershipId { get; set; }
    public string Role { get; set; } = string.Empty;
}

/// <summary>A role held only within one application, for one member of one company.</summary>
public class MembershipApplicationRoleRecord
{
    public Guid Id { get; set; }
    public Guid MembershipId { get; set; }
    public string ClientId { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
}

/// <summary>A company's subscription to an application, by OpenIddict client id.</summary>
public class TenantApplicationRecord
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public string ClientId { get; set; } = string.Empty;
    public bool IsActive { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; }
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

public class EmailOutboxMessage
{
    public Guid Id { get; set; }
    public string ToEmail { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public string Body { get; set; } = string.Empty;
    public string Status { get; set; } = EmailOutboxStatus.Pending;
    public int Attempts { get; set; }
    public string? LastError { get; set; }

    // DateTime (UTC), not DateTimeOffset: the SQLite provider can't translate
    // relational (<=, >=) comparisons on DateTimeOffset columns, only equality,
    // and the dispatcher needs a "NextAttemptAt <= now" range query.
    public DateTime CreatedAt { get; set; }
    public DateTime NextAttemptAt { get; set; }
    public DateTime? SentAt { get; set; }
}

public static class EmailOutboxStatus
{
    public const string Pending = "Pending";
    public const string Sent = "Sent";
    public const string Failed = "Failed";
}
