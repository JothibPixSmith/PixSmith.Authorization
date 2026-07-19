namespace PixSmith.Authorization.UITests.Support;

/// <summary>
/// This layer drives the real, already-running AuthServer + Blazor client (there is no
/// in-process host like the integration tests use) — start both before running these
/// scenarios, or point UITEST_BASE_URL at wherever they're deployed.
/// </summary>
public static class TestSettings
{
    public static string BaseUrl =>
        Environment.GetEnvironmentVariable("UITEST_BASE_URL") ?? "https://localhost:7100";
}
