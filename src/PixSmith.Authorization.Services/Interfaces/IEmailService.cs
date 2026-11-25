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
	}
}
