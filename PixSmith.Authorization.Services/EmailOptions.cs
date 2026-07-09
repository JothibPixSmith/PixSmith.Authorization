namespace PixSmith.Authorization.Services;

public sealed class EmailOptions
{
	public string FromAddress { get; set; } = "noreply@localhost";
	public string FromName { get; set; } = "PixSmith Authorization";
	public SmtpOptions Smtp { get; set; } = new();
	public EmailOutboxOptions Outbox { get; set; } = new();
}

public sealed class SmtpOptions
{
	public string Host { get; set; } = "localhost";
	public int Port { get; set; } = 1025;
	public bool EnableSsl { get; set; }
	public string Username { get; set; } = string.Empty;
	public string Password { get; set; } = string.Empty;
}

public sealed class EmailOutboxOptions
{
	public int PollIntervalSeconds { get; set; } = 5;
	public int MaxAttempts { get; set; } = 5;
}
