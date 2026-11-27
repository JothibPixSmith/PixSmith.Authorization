using System;
using System.Collections.Generic;
using System.Text;

namespace PixSmith.Authorization.Services.Interfaces
{
	public interface IEmailService
	{
		Task SendEmailConfirmationAsync(string email, string confirmationLink, CancellationToken ct = default);
		Task SendPasswordResetAsync(string email, string resetLink, CancellationToken ct = default);
		Task SendWelcomeEmailAsync(string email, string fullName, CancellationToken ct = default);

		/// <summary>
		/// Sent when someone tries to register an address that already has an account. The
		/// registration endpoint answers identically whether or not the account exists, so this
		/// is how the real owner — and only the real owner — learns of the attempt.
		/// </summary>
		Task SendRegistrationAttemptNoticeAsync(string email, string signInLink, CancellationToken ct = default);

		/// <summary>
		/// Sent when a run of failed sign-in attempts locks an account. The login page shows
		/// the same "Invalid email or password." for a locked account as for an address with no
		/// account at all, so this is how the real owner — and only the real owner — learns
		/// why they cannot get in, and that someone is guessing at their password.
		/// </summary>
		Task SendAccountLockedAsync(string email, DateTimeOffset lockoutEnd, string resetPasswordLink, CancellationToken ct = default);

		/// <summary>
		/// Sent when someone signs in with the right password to an account whose address has
		/// never been confirmed. The login page answers such an attempt exactly as it answers a
		/// wrong password — every account starts out unconfirmed, so a message naming the
		/// reason would disclose that the address is registered — which leaves this as the only
		/// way to tell the one person entitled to know, and hand them a fresh link.
		/// </summary>
		Task SendEmailConfirmationReminderAsync(string email, string confirmationLink, CancellationToken ct = default);
	}
}
