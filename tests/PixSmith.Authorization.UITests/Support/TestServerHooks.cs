using System.Diagnostics;
using Reqnroll;

namespace PixSmith.Authorization.UITests.Support;

/// <summary>
/// Boots the real AuthServer (out-of-process, real Kestrel/HTTPS) once for the whole test run,
/// so pressing "Run Tests" in Visual Studio's Test Explorer is enough on its own - no need to
/// separately `dotnet run` the API first. If something is already answering at
/// TestSettings.BaseUrl (e.g. you're running the API yourself via F5 to debug it), that
/// instance is reused instead and left alone on teardown.
/// </summary>
[Binding]
public static class TestServerHooks
{
    private static Process? managedServerProcess;
    private static string? tempDatabasePath;

    [BeforeTestRun]
    public static async Task StartServerAsync()
    {
        if (Environment.GetEnvironmentVariable("UITEST_MANAGE_SERVER") == "false")
            return;

        if (await IsServerRespondingAsync())
        {
            Console.WriteLine($"[TestServerHooks] Reusing server already running at {TestSettings.BaseUrl}.");
            return;
        }

        var repoRoot = FindRepoRoot();
        var apiProjectDirectory = Path.Combine(repoRoot, "src", "AuthServer", "AuthServer.API");
        tempDatabasePath = Path.Combine(Path.GetTempPath(), $"pixsmith-uitest-{Guid.NewGuid():N}.db");

        Console.WriteLine($"[TestServerHooks] Starting AuthServer.API at {TestSettings.BaseUrl} (db: {tempDatabasePath}).");

        var startInfo = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = apiProjectDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        startInfo.ArgumentList.Add("run");
        startInfo.ArgumentList.Add("--no-launch-profile");
        startInfo.ArgumentList.Add("--urls");
        startInfo.ArgumentList.Add(TestSettings.BaseUrl);

        // Isolated from the developer's real auth.db / dev secrets: Development is kept (not
        // "Testing") because Kestrel's HTTPS endpoint and OpenIddict's dev signing/encryption
        // certs both key off it, and that's the same setup already proven to work for local runs.
        startInfo.EnvironmentVariables["ASPNETCORE_ENVIRONMENT"] = "Development";
        startInfo.EnvironmentVariables["Database__Provider"] = "Sqlite";
        startInfo.EnvironmentVariables["ConnectionStrings__DefaultConnection"] = $"Data Source={tempDatabasePath}";
        startInfo.EnvironmentVariables["OpenIddict__BlazorClient__BaseUri"] = TestSettings.BaseUrl;

        managedServerProcess = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Failed to start AuthServer.API for UI tests.");

        // Must drain these asynchronously - once the OS pipe buffer fills, the child process
        // blocks on its next write and the server never finishes starting up.
        managedServerProcess.OutputDataReceived += (_, _) => { };
        managedServerProcess.ErrorDataReceived += (_, _) => { };
        managedServerProcess.BeginOutputReadLine();
        managedServerProcess.BeginErrorReadLine();

        await WaitUntilReadyAsync(TimeSpan.FromMinutes(3));
        Console.WriteLine("[TestServerHooks] AuthServer.API is ready.");
    }

    [AfterTestRun]
    public static void StopServer()
    {
        if (managedServerProcess is null) return;

        try
        {
            if (!managedServerProcess.HasExited)
                managedServerProcess.Kill(entireProcessTree: true);
        }
        finally
        {
            managedServerProcess.Dispose();
            managedServerProcess = null;
        }

        if (tempDatabasePath is not null)
        {
            foreach (var suffix in new[] { "", "-shm", "-wal" })
            {
                try { File.Delete(tempDatabasePath + suffix); } catch (IOException) { /* best effort */ }
            }
            tempDatabasePath = null;
        }
    }

    private static async Task WaitUntilReadyAsync(TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        Exception? lastError = null;

        while (DateTime.UtcNow < deadline)
        {
            if (managedServerProcess!.HasExited)
                throw new InvalidOperationException(
                    $"AuthServer.API exited early (code {managedServerProcess.ExitCode}) while starting up for UI tests.");

            try
            {
                if (await IsServerRespondingAsync())
                    return;
            }
            catch (Exception ex)
            {
                lastError = ex;
            }

            await Task.Delay(500);
        }

        throw new TimeoutException(
            $"AuthServer.API did not become ready at {TestSettings.BaseUrl} within {timeout}.", lastError);
    }

    private static async Task<bool> IsServerRespondingAsync()
    {
        using var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(3) };

        try
        {
            var response = await client.GetAsync($"{TestSettings.BaseUrl}/login");
            return response.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "OAuthSolution.sln")))
            dir = dir.Parent;

        return dir?.FullName
            ?? throw new InvalidOperationException($"Could not locate OAuthSolution.sln above {AppContext.BaseDirectory}.");
    }
}
