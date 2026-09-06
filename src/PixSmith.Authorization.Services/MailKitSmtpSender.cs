using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;
using PixSmith.Authorization.Services.Interfaces;

namespace PixSmith.Authorization.Services;

public sealed class MailKitSmtpSender(IOptions<EmailOptions> options) : ISmtpSender
{
	private readonly EmailOptions options = options.Value;

	public async Task SendAsync(string toEmail, string subject, string htmlBody, CancellationToken ct = default)
	{
		var message = new MimeMessage();
		message.From.Add(new MailboxAddress(options.FromName, options.FromAddress));
		message.To.Add(MailboxAddress.Parse(toEmail));
		message.Subject = subject;
		message.Body = new BodyBuilder { HtmlBody = htmlBody }.ToMessageBody();

		using var client = new SmtpClient();

		var socketOptions = options.Smtp.EnableSsl
			? SecureSocketOptions.SslOnConnect
			: SecureSocketOptions.None;

		await client.ConnectAsync(options.Smtp.Host, options.Smtp.Port, socketOptions, ct);

		if (!string.IsNullOrEmpty(options.Smtp.Username))
			await client.AuthenticateAsync(options.Smtp.Username, options.Smtp.Password, ct);

		await client.SendAsync(message, ct);
		await client.DisconnectAsync(true, ct);
	}
}
