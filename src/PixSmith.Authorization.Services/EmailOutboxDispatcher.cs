using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Services.Interfaces;

namespace PixSmith.Authorization.Services;

/// <summary>
/// Polls the email outbox and sends pending messages via ISmtpSender, so a slow or
/// unreachable mail server never blocks the request that queued the email (registration,
/// forgot-password, etc). Failed sends are retried with backoff up to MaxAttempts.
/// </summary>
public sealed class EmailOutboxDispatcher(
	IServiceScopeFactory scopeFactory,
	IOptions<EmailOptions> options,
	ILogger<EmailOutboxDispatcher> logger) : BackgroundService
{
	private const int BatchSize = 20;

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		var interval = TimeSpan.FromSeconds(Math.Max(1, options.Value.Outbox.PollIntervalSeconds));
		using var timer = new PeriodicTimer(interval);

		do
		{
			try
			{
				await DispatchPendingAsync(stoppingToken);
			}
			catch (Exception ex) when (ex is not OperationCanceledException)
			{
				logger.LogError(ex, "Email outbox dispatch cycle failed.");
			}
		}
		while (await timer.WaitForNextTickAsync(stoppingToken));
	}

	private async Task DispatchPendingAsync(CancellationToken ct)
	{
		await using var scope = scopeFactory.CreateAsyncScope();
		var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
		var sender = scope.ServiceProvider.GetRequiredService<ISmtpSender>();
		var maxAttempts = options.Value.Outbox.MaxAttempts;

		var now = DateTime.UtcNow;
		var pending = await context.EmailOutboxMessages
			.Where(m => m.Status == EmailOutboxStatus.Pending && m.NextAttemptAt <= now)
			.OrderBy(m => m.CreatedAt)
			.Take(BatchSize)
			.ToListAsync(ct);

		foreach (var message in pending)
		{
			message.Attempts++;

			try
			{
				await sender.SendAsync(message.ToEmail, message.Subject, message.Body, ct);
				message.Status = EmailOutboxStatus.Sent;
				message.SentAt = DateTime.UtcNow;
			}
			catch (Exception ex) when (ex is not OperationCanceledException)
			{
				message.LastError = ex.Message;
				logger.LogWarning(ex, "Failed to send email to {ToEmail} (attempt {Attempt})", message.ToEmail, message.Attempts);

				if (message.Attempts >= maxAttempts)
				{
					message.Status = EmailOutboxStatus.Failed;
				}
				else
				{
					var backoff = TimeSpan.FromMinutes(Math.Min(30, Math.Pow(2, message.Attempts)));
					message.NextAttemptAt = DateTime.UtcNow.Add(backoff);
				}
			}
		}

		if (pending.Count > 0)
			await context.SaveChangesAsync(ct);
	}
}
