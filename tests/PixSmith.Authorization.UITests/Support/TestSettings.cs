namespace PixSmith.Authorization.UITests.Support;

/// <summary>
/// TestServerHooks auto-starts AuthServer.API at this URL if nothing's already listening there,
/// so scenarios normally need no manual setup. Point UITEST_BASE_URL elsewhere to run against
/// an already-running instance (local F5 debugging, a deployed environment, etc.) instead.
/// </summary>
public static class TestSettings
{
    public static string BaseUrl =>
        Environment.GetEnvironmentVariable("UITEST_BASE_URL") ?? "https://localhost:7100";
}
