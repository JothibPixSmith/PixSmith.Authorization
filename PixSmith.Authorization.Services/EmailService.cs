using PixSmith.Authorization.Services.Interfaces;

namespace PixSmith.Authorization.Services
{
	public class EmailService : IEmailService
	{
		public Task SendEmailConfirmationAsync(string email, string confirmationLink, CancellationToken ct = default)
		{
			//throw new NotImplementedException();
			return Task.CompletedTask;
		}

		public Task SendPasswordResetAsync(string email, string resetLink, CancellationToken ct = default)
		{
			//throw new NotImplementedException();
			return Task.CompletedTask;
		}

		public Task SendWelcomeEmailAsync(string email, string fullName, CancellationToken ct = default)
		{
			//throw new NotImplementedException();
			return Task.CompletedTask;
		}
	}
}
