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

		public Task SendRegistrationAttemptNoticeAsync(string email, string signInLink, CancellationToken ct = default) =>
			outbox.EnqueueAsync(
				email,
				"Someone tried to register with your email address",
				$"""
				<p>We received a registration attempt for an account that already exists with this
				email address. No new account was created and nothing has changed.</p>
				<p>If this was you, sign in instead: <a href="{WebUtility.HtmlEncode(signInLink)}">Sign in</a></p>
				<p>If it wasn't you, you can ignore this email. Consider changing your password if
				you believe someone is targeting your account.</p>
				""",
				ct);

		public Task SendEmailConfirmationReminderAsync(string email, string confirmationLink, CancellationToken ct = default) =>
			outbox.EnqueueAsync(
				email,
				"Confirm your email address to sign in",
				$"""
				<p>You just tried to sign in with the right password, but this email address has
				never been confirmed — so we could not let you in. Confirm it with the link
				below and sign in again.</p>
				<p><a href="{WebUtility.HtmlEncode(confirmationLink)}">Confirm email</a></p>
				<p>The sign-in page could not tell you this. It answers every failed attempt the
				same way on purpose, so that nobody can use it to work out which addresses have
				accounts here.</p>
				<p>If this wasn't you, ignore this email. Nobody was signed in and nothing has
				changed — but somebody knows the password to this account, so consider resetting
				it once you are in.</p>
				""",
				ct);

		public Task SendAccountLockedAsync(string email, DateTimeOffset lockoutEnd, string resetPasswordLink, CancellationToken ct = default) =>
			outbox.EnqueueAsync(
				email,
				"Your account is temporarily locked",
				$"""
				<p>Too many failed sign-in attempts locked your account. It unlocks automatically
				at {WebUtility.HtmlEncode(lockoutEnd.ToString("f", System.Globalization.CultureInfo.InvariantCulture))} UTC, and you can then try again.</p>
				<p>If that was you, nothing else is needed — wait for the lock to lift, or
				<a href="{WebUtility.HtmlEncode(resetPasswordLink)}">reset your password</a> if you have forgotten it.</p>
				<p>If it wasn't you, someone is guessing at your password. Your password still
				works and has not changed, but we recommend resetting it with the link above.</p>
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
