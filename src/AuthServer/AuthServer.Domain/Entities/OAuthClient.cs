using PixSmith.Authorization.Domain.Enums;

namespace PixSmith.Authorization.Domain.Entities;

/// <summary>
/// Represents a registered OAuth 2.0 / OIDC client application.
/// </summary>
public sealed class OAuthClient
{
    private readonly List<string> _redirectUris = [];
    private readonly List<string> _allowedScopes = [];
    private readonly List<string> _allowedGrantTypes = [];
    private readonly List<string> _corsOrigins = [];

    private OAuthClient() { }

    public Guid Id { get; private set; }
    public string ClientId { get; private set; } = string.Empty;
    public string ClientSecret { get; private set; } = string.Empty;
    public string DisplayName { get; private set; } = string.Empty;
    public string? Description { get; private set; }
    public string? LogoUri { get; private set; }
    public ClientType ClientType { get; private set; }
    public bool IsActive { get; private set; }
    public bool RequireConsent { get; private set; }
    public bool RequirePkce { get; private set; }
    public bool AllowOfflineAccess { get; private set; }
    public int AccessTokenLifetimeSeconds { get; private set; }
    public int IdentityTokenLifetimeSeconds { get; private set; }
    public int? AbsoluteRefreshTokenLifetimeSeconds { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public Guid CreatedByUserId { get; private set; }

    public IReadOnlyList<string> RedirectUris => _redirectUris.AsReadOnly();
    public IReadOnlyList<string> AllowedScopes => _allowedScopes.AsReadOnly();
    public IReadOnlyList<string> AllowedGrantTypes => _allowedGrantTypes.AsReadOnly();
    public IReadOnlyList<string> CorsOrigins => _corsOrigins.AsReadOnly();

    public static OAuthClient Reconstitute(
        Guid id,
        string clientId,
        string clientSecret,
        string displayName,
        string? description,
        string? logoUri,
        ClientType clientType,
        bool isActive,
        bool requireConsent,
        bool requirePkce,
        bool allowOfflineAccess,
        int accessTokenLifetimeSeconds,
        int identityTokenLifetimeSeconds,
        int? absoluteRefreshTokenLifetimeSeconds,
        DateTimeOffset createdAt,
        Guid createdByUserId,
        IEnumerable<string> redirectUris,
        IEnumerable<string> allowedScopes,
        IEnumerable<string> allowedGrantTypes,
        IEnumerable<string> corsOrigins)
    {
        var client = new OAuthClient();
        client.Id = id;
        client.ClientId = clientId;
        client.ClientSecret = clientSecret;
        client.DisplayName = displayName;
        client.Description = description;
        client.LogoUri = logoUri;
        client.ClientType = clientType;
        client.IsActive = isActive;
        client.RequireConsent = requireConsent;
        client.RequirePkce = requirePkce;
        client.AllowOfflineAccess = allowOfflineAccess;
        client.AccessTokenLifetimeSeconds = accessTokenLifetimeSeconds;
        client.IdentityTokenLifetimeSeconds = identityTokenLifetimeSeconds;
        client.AbsoluteRefreshTokenLifetimeSeconds = absoluteRefreshTokenLifetimeSeconds;
        client.CreatedAt = createdAt;
        client.CreatedByUserId = createdByUserId;
        client._redirectUris.AddRange(redirectUris);
        client._allowedScopes.AddRange(allowedScopes);
        client._allowedGrantTypes.AddRange(allowedGrantTypes);
        client._corsOrigins.AddRange(corsOrigins);
        return client;
    }

    public static OAuthClient Create(
        string clientId,
        string clientSecret,
        string displayName,
        ClientType clientType,
        Guid createdByUserId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentException.ThrowIfNullOrWhiteSpace(clientSecret);
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);

        return new OAuthClient
        {
            Id = Guid.NewGuid(),
            ClientId = clientId.Trim(),
            ClientSecret = clientSecret,
            DisplayName = displayName.Trim(),
            ClientType = clientType,
            IsActive = true,
            RequireConsent = false,
            RequirePkce = clientType == ClientType.Public,
            AllowOfflineAccess = true,
            AccessTokenLifetimeSeconds = 3600,
            IdentityTokenLifetimeSeconds = 300,
            AbsoluteRefreshTokenLifetimeSeconds = 2592000, // 30 days
            CreatedAt = DateTimeOffset.UtcNow,
            CreatedByUserId = createdByUserId,
        };
    }

    public void AddRedirectUri(string uri)
    {
        if (!_redirectUris.Contains(uri)) _redirectUris.Add(uri);
    }

    public void RemoveRedirectUri(string uri) => _redirectUris.Remove(uri);

    public void AddScope(string scope)
    {
        if (!_allowedScopes.Contains(scope)) _allowedScopes.Add(scope);
    }

    public void AddGrantType(string grantType)
    {
        if (!_allowedGrantTypes.Contains(grantType)) _allowedGrantTypes.Add(grantType);
    }

    public void AddCorsOrigin(string origin)
    {
        if (!_corsOrigins.Contains(origin)) _corsOrigins.Add(origin);
    }

    public void Update(string displayName, string? description, string? logoUri,
        bool requireConsent, bool allowOfflineAccess,
        int accessTokenLifetime, int identityTokenLifetime)
    {
        DisplayName = displayName;
        Description = description;
        LogoUri = logoUri;
        RequireConsent = requireConsent;
        AllowOfflineAccess = allowOfflineAccess;
        AccessTokenLifetimeSeconds = accessTokenLifetime;
        IdentityTokenLifetimeSeconds = identityTokenLifetime;
    }

    public void Deactivate() => IsActive = false;
    public void Activate() => IsActive = true;

    public bool IsRedirectUriAllowed(string uri) => _redirectUris.Contains(uri);
    public bool IsScopeAllowed(string scope) => _allowedScopes.Contains(scope);
    public bool IsGrantTypeAllowed(string grantType) => _allowedGrantTypes.Contains(grantType);
}
