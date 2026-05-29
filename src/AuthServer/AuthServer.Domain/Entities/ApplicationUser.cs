using PixSmith.Authorization.Domain.Enums;
using PixSmith.Authorization.Domain.Events;

namespace PixSmith.Authorization.Domain.Entities;

/// <summary>
/// Core user entity - the heart of the domain.
/// All identity/auth attributes live here, framework-agnostic.
/// </summary>
public sealed class ApplicationUser
{
    private readonly List<UserRole> _roles = [];
    private readonly List<ExternalLoginProvider> _externalLogins = [];
    private readonly List<DomainEvent> _domainEvents = [];

    // Private constructor enforces factory method usage
    private ApplicationUser() { }

    public Guid Id { get; private set; }
    public string Username { get; private set; } = string.Empty;
    public string Email { get; private set; } = string.Empty;
    public string NormalizedEmail { get; private set; } = string.Empty;
    public string? PasswordHash { get; private set; }
    public string? FirstName { get; private set; }
    public string? LastName { get; private set; }
    public string? PhoneNumber { get; private set; }
    public bool PhoneNumberConfirmed { get; private set; }
    public bool EmailConfirmed { get; private set; }
    public bool TwoFactorEnabled { get; private set; }
    public bool IsActive { get; private set; }
    public bool IsLocked { get; private set; }
    public DateTimeOffset? LockoutEnd { get; private set; }
    public int AccessFailedCount { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset? LastLoginAt { get; private set; }
    public string? ProfilePictureUrl { get; private set; }

    public IReadOnlyList<UserRole> Roles => _roles.AsReadOnly();
    public IReadOnlyList<ExternalLoginProvider> ExternalLogins => _externalLogins.AsReadOnly();
    public IReadOnlyList<DomainEvent> DomainEvents => _domainEvents.AsReadOnly();

    // ─── Factory ───────────────────────────────────────────────────────────

    public static ApplicationUser Create(
        string username,
        string email,
        string? firstName = null,
        string? lastName = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        var user = new ApplicationUser
        {
            Id = Guid.NewGuid(),
            Username = username.Trim(),
            Email = email.Trim(),
            NormalizedEmail = email.Trim().ToUpperInvariant(),
            FirstName = firstName?.Trim(),
            LastName = lastName?.Trim(),
            IsActive = true,
            IsLocked = false,
            CreatedAt = DateTimeOffset.UtcNow,
        };

        user._domainEvents.Add(new UserCreatedEvent(user.Id, user.Email));
        return user;
    }

    // Used by the repository layer to rebuild the aggregate from persisted data.
    public static ApplicationUser Reconstitute(
        Guid id, string username, string email, string normalizedEmail, string? passwordHash,
        string? firstName, string? lastName, string? phoneNumber,
        bool emailConfirmed, bool twoFactorEnabled, bool isActive, bool isLocked,
        DateTimeOffset? lockoutEnd, int accessFailedCount,
        DateTimeOffset createdAt, DateTimeOffset? lastLoginAt, string? profilePictureUrl,
        IEnumerable<UserRole>? roles = null,
        IEnumerable<ExternalLoginProvider>? externalLogins = null)
    {
        var user = new ApplicationUser
        {
            Id = id,
            Username = username,
            Email = email,
            NormalizedEmail = normalizedEmail,
            PasswordHash = passwordHash,
            FirstName = firstName,
            LastName = lastName,
            PhoneNumber = phoneNumber,
            EmailConfirmed = emailConfirmed,
            TwoFactorEnabled = twoFactorEnabled,
            IsActive = isActive,
            IsLocked = isLocked,
            LockoutEnd = lockoutEnd,
            AccessFailedCount = accessFailedCount,
            CreatedAt = createdAt,
            LastLoginAt = lastLoginAt,
            ProfilePictureUrl = profilePictureUrl,
        };
        if (roles is not null)
            foreach (var r in roles) user._roles.Add(r);
        if (externalLogins is not null)
            foreach (var e in externalLogins) user._externalLogins.Add(e);
        return user;
    }

    // ─── Behaviour ─────────────────────────────────────────────────────────

    public void SetPasswordHash(string hash)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hash);
        PasswordHash = hash;
    }

    public void ConfirmEmail()
    {
        EmailConfirmed = true;
        _domainEvents.Add(new UserEmailConfirmedEvent(Id));
    }

    public void RecordSuccessfulLogin()
    {
        LastLoginAt = DateTimeOffset.UtcNow;
        AccessFailedCount = 0;
        IsLocked = false;
        LockoutEnd = null;
    }

    public void RecordFailedLogin(int maxFailures = 5, TimeSpan? lockoutDuration = null)
    {
        AccessFailedCount++;
        if (AccessFailedCount >= maxFailures)
        {
            IsLocked = true;
            LockoutEnd = DateTimeOffset.UtcNow.Add(lockoutDuration ?? TimeSpan.FromMinutes(15));
            _domainEvents.Add(new UserLockedOutEvent(Id, LockoutEnd.Value));
        }
    }

    public void Unlock()
    {
        IsLocked = false;
        LockoutEnd = null;
        AccessFailedCount = 0;
    }

    public void Deactivate()
    {
        IsActive = false;
        _domainEvents.Add(new UserDeactivatedEvent(Id));
    }

    public void Activate() => IsActive = true;

    public bool IsLockedOut() =>
        IsLocked && (LockoutEnd == null || LockoutEnd > DateTimeOffset.UtcNow);

    public void AssignRole(string roleName)
    {
        if (_roles.Any(r => r.Name == roleName)) return;
        _roles.Add(new UserRole(Id, roleName));
    }

    public void RemoveRole(string roleName)
    {
        var role = _roles.FirstOrDefault(r => r.Name == roleName);
        if (role is not null) _roles.Remove(role);
    }

    public bool HasRole(string roleName) =>
        _roles.Any(r => r.Name.Equals(roleName, StringComparison.OrdinalIgnoreCase));

    public void AddExternalLogin(string provider, string providerKey, string? displayName = null)
    {
        if (_externalLogins.Any(e => e.Provider == provider && e.ProviderKey == providerKey))
            return;

        _externalLogins.Add(new ExternalLoginProvider(provider, providerKey, displayName));
    }

    public void UpdateProfile(string? firstName, string? lastName, string? phoneNumber, string? profilePictureUrl)
    {
        FirstName = firstName?.Trim();
        LastName = lastName?.Trim();
        PhoneNumber = phoneNumber?.Trim();
        ProfilePictureUrl = profilePictureUrl;
    }

    public void UpdateCoreFields(string username, string email, bool emailConfirmed)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        ArgumentException.ThrowIfNullOrWhiteSpace(email);
        Username = username.Trim();
        Email = email.Trim();
        NormalizedEmail = email.Trim().ToUpperInvariant();
        EmailConfirmed = emailConfirmed;
    }

    public void EnableTwoFactor() => TwoFactorEnabled = true;
    public void DisableTwoFactor() => TwoFactorEnabled = false;

    public void ClearDomainEvents() => _domainEvents.Clear();

    public string FullName => $"{FirstName} {LastName}".Trim();
}
