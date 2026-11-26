namespace PixSmith.Authorization.API.Models;

/// <summary>
/// The logout confirmation shown when an end-session request arrives without a valid
/// <c>id_token_hint</c>. The original request parameters are carried through the form so the
/// confirmed POST can still honour the relying party's redirect.
/// </summary>
public sealed class LogoutModel
{
    /// <summary>The application asking, when it identified itself. May be null.</summary>
    public string? ClientId { get; set; }

    public string? PostLogoutRedirectUri { get; set; }

    /// <summary>Opaque relying-party value that must survive the round trip.</summary>
    public string? State { get; set; }
}
