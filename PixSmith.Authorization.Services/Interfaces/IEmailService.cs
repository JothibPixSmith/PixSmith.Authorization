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
	}
}
