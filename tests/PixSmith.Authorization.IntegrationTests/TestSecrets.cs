namespace PixSmith.Authorization.IntegrationTests;

/// <summary>
/// Configuration the host refuses to start without, supplied once for the test process.
///
/// <para>
/// Both factories call this. It used to live in one of them, which meant running the other
/// class on its own — <c>--filter</c>, or a single test from an IDE — failed at startup on a
/// missing M2M secret. A test suite that only passes when the whole thing runs in one order is
/// a trap, so the dependency is explicit and shared instead.
/// </para>
/// </summary>
internal static class TestSecrets
{
    private static readonly object Gate = new();
    private static bool _applied;

    public static void Ensure()
    {
        lock (Gate)
        {
            if (_applied) return;

            // Deliberately not in appsettings.json: a secret committed to the repository is a
            // known secret, so the host requires it per environment.
            Environment.SetEnvironmentVariable(
                "OpenIddict__M2MClient__ClientSecret",
                "integration-tests-only-not-a-real-secret");

            _applied = true;
        }
    }
}
