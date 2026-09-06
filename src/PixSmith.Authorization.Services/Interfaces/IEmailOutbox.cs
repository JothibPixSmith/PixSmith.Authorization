namespace PixSmith.Authorization.Services.Interfaces;

public interface IEmailOutbox
{
	Task EnqueueAsync(string toEmail, string subject, string htmlBody, CancellationToken ct = default);
}
