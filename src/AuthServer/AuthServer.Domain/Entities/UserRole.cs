namespace AuthServer.Domain.Entities;

/// <summary>Value object for a role assigned to a user.</summary>
public sealed class UserRole
{
    public Guid UserId { get; }
    public string Name { get; }
    public DateTimeOffset AssignedAt { get; }

    public UserRole(Guid userId, string name)
    {
        UserId = userId;
        Name = name;
        AssignedAt = DateTimeOffset.UtcNow;
    }
}

/// <summary>Value object for an external SSO login provider link.</summary>
public sealed class ExternalLoginProvider
{
    public string Provider { get; }
    public string ProviderKey { get; }
    public string? DisplayName { get; }
    public DateTimeOffset LinkedAt { get; }

    public ExternalLoginProvider(string provider, string providerKey, string? displayName)
    {
        Provider = provider;
        ProviderKey = providerKey;
        DisplayName = displayName;
        LinkedAt = DateTimeOffset.UtcNow;
    }
}
