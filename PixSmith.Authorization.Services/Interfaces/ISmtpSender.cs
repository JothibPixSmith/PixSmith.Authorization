namespace PixSmith.Authorization.Services.Interfaces;

public interface ISmtpSender
{
	Task SendAsync(string toEmail, string subject, string htmlBody, CancellationToken ct = default);
}
