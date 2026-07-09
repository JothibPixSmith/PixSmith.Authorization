using System.Net;
using PixSmith.Authorization.Services.Interfaces;

namespace PixSmith.Authorization.Services
{
	public class EmailService(IEmailOutbox outbox) : IEmailService
	{
		public Task SendEmailConfirmationAsync(string email, string confirmationLink, CancellationToken ct = default) =>
			outbox.EnqueueAsync(
				email,
				"Confirm your email address",
				$"""
				<p>Welcome! Please confirm your email address by clicking the link below.</p>
				<p><a href="{WebUtility.HtmlEncode(confirmationLink)}">Confirm email</a></p>
				<p>If you didn't create this account, you can ignore this email.</p>
				""",
				ct);

		public Task SendPasswordResetAsync(string email, string resetLink, CancellationToken ct = default) =>
			outbox.EnqueueAsync(
				email,
				"Reset your password",
				$"""
				<p>We received a request to reset your password. Click the link below to choose a new one.</p>
				<p><a href="{WebUtility.HtmlEncode(resetLink)}">Reset password</a></p>
				<p>If you didn't request this, you can safely ignore this email — your password will not change.</p>
				""",
				ct);

		public Task SendWelcomeEmailAsync(string email, string fullName, CancellationToken ct = default) =>
			outbox.EnqueueAsync(
				email,
				"Welcome to PixSmith",
				$"""
				<p>Hi {WebUtility.HtmlEncode(fullName)},</p>
				<p>Your account is ready to go.</p>
				""",
				ct);
	}
}
