using Microsoft.AspNetCore.Mvc;

namespace PixSmith.Authorization.API.Models;

/// <summary>
/// The end-user verification page for the device authorization grant: the human types the
/// code their device displayed and approves the request.
/// </summary>
public sealed class VerifyModel
{
    /// <summary>
    /// Bound from <c>user_code</c>, not <c>UserCode</c>: that is the parameter name OpenIddict
    /// reads to resolve the pending device request. Posting the PascalCase name leaves the
    /// server unable to match the code, and the approval fails with a message about the code
    /// being invalid rather than about the field name.
    /// </summary>
    [FromForm(Name = "user_code")]
    public string? UserCode { get; set; }

    /// <summary>The application asking, shown so the person can recognise it.</summary>
    public string? ClientId { get; set; }

    /// <summary>Scopes requested, so approval is informed rather than blind.</summary>
    public string? Scope { get; set; }

    public string? Error { get; set; }
}
