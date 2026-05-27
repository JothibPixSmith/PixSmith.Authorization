namespace PixSmith.Authorization.Domain.Enums;

public enum ClientType
{
    /// <summary>Confidential client - can securely hold a client secret (e.g. server-side app)</summary>
    Confidential = 0,

    /// <summary>Public client - cannot hold a secret securely (e.g. SPA, mobile app); requires PKCE</summary>
    Public = 1,

    /// <summary>Hybrid - combination of public and confidential flows</summary>
    Hybrid = 2,
}

public enum UserStatus
{
    Active = 0,
    Inactive = 1,
    Locked = 2,
    PendingEmailConfirmation = 3,
}

public enum TokenType
{
    AccessToken = 0,
    RefreshToken = 1,
    IdToken = 2,
    AuthorizationCode = 3,
}
