using PixSmith.Authorization.Services.Interfaces;
using System;
using System.Collections.Generic;
using System.Text;

namespace PixSmith.Authorization.Services
{
	public class EmailService : IEmailService
	{
		public Task SendEmailConfirmationAsync(string email, string confirmationLink, CancellationToken ct = default)
		{
			throw new NotImplementedException();
		}

		public Task SendPasswordResetAsync(string email, string resetLink, CancellationToken ct = default)
		{
			throw new NotImplementedException();
		}

		public Task SendWelcomeEmailAsync(string email, string fullName, CancellationToken ct = default)
		{
			throw new NotImplementedException();
		}
	}
}
