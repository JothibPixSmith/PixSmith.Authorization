using Microsoft.AspNetCore.Components.WebAssembly.Http;

namespace BlazorClient.Services;

/// <summary>
/// Sets credentials: 'include' on every fetch so the BFF session cookie
/// is sent on cross-origin requests from localhost:7200 → localhost:7300.
/// </summary>
public sealed class IncludeCredentialsHandler : DelegatingHandler
{
    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        request.SetBrowserRequestCredentials(BrowserRequestCredentials.Include);
        return base.SendAsync(request, cancellationToken);
    }
}
