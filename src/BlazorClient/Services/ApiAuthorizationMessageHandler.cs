using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.WebAssembly.Authentication;

namespace PixSmith.Authorization.BlazorClient.Services;

/// <summary>
/// Attaches the access token to calls against this server's own API.
///
/// <para>
/// The base handler refuses to send tokens to any origin not explicitly authorized, which is
/// what stops a token leaking to a third-party host if a base address is ever misconfigured.
/// Here the only authorized origin is the app's own, since the API hosts this client.
/// </para>
/// </summary>
public sealed class ApiAuthorizationMessageHandler : AuthorizationMessageHandler
{
    public ApiAuthorizationMessageHandler(
        IAccessTokenProvider provider, NavigationManager navigation)
        : base(provider, navigation)
    {
        ConfigureHandler(authorizedUrls: [navigation.BaseUri]);
    }
}
