using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Services.Interfaces;

namespace PixSmith.Authorization.Services;

public sealed class EmailOutbox(ApplicationDbContext context) : IEmailOutbox
{
	public async Task EnqueueAsync(string toEmail, string subject, string htmlBody, CancellationToken ct = default)
	{
		var now = DateTime.UtcNow;
		context.EmailOutboxMessages.Add(new EmailOutboxMessage
		{
			Id = Guid.NewGuid(),
			ToEmail = toEmail,
			Subject = subject,
			Body = htmlBody,
			Status = EmailOutboxStatus.Pending,
			CreatedAt = now,
			NextAttemptAt = now,
		});

		await context.SaveChangesAsync(ct);
	}
}
