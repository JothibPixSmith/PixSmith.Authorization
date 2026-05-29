using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Services;
using PixSmith.Authorization.Services.Interfaces;

namespace PixSmith.Authorization.API;

public sealed class AdminUserSeeder(
    IServiceProvider serviceProvider,
    IConfiguration configuration,
    ILogger<AdminUserSeeder> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken ct)
    {
        var email    = configuration["AdminSeed:Email"];
        var password = configuration["AdminSeed:Password"];

        if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
            return;

        await using var scope = serviceProvider.CreateAsyncScope();
        var userService  = scope.ServiceProvider.GetRequiredService<IUserService>();
        var adminService = scope.ServiceProvider.GetRequiredService<IAdminService>();

        var existing = await userService.GetByEmailAsync(email, ct);
        if (existing.IsSuccess)
        {
            logger.LogDebug("Admin seed skipped — {Email} already exists.", email);
            return;
        }

        var username = configuration["AdminSeed:Username"] is { Length: > 0 } u
            ? u
            : email.Split('@')[0];

        var result = await userService.RegisterAsync(
            new RegisterUserRequest(username, email, password, password, null, null), ct);

        if (!result.IsSuccess)
        {
            logger.LogWarning("Admin seed failed for {Email}: {Error}", email, result.Error);
            return;
        }

        var roleResult = await adminService.AssignRoleAsync(result.Value!.Id, "Admin", ct);
        if (roleResult.IsSuccess)
            logger.LogInformation("Initial admin user {Email} created and assigned Admin role.", email);
        else
            logger.LogWarning("Admin user {Email} created but role assignment failed: {Error}", email, roleResult.Error);
    }

    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
}
