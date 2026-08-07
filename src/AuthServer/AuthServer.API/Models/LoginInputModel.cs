using System.ComponentModel.DataAnnotations;

namespace PixSmith.Authorization.API.Models;

public sealed class LoginInputModel
{
	[Required(ErrorMessage = "Email is required.")]
	[EmailAddress(ErrorMessage = "Enter a valid email address.")]
	public string Email { get; set; } = string.Empty;

	[Required(ErrorMessage = "Password is required.")]
	[DataType(DataType.Password)]
	public string Password { get; set; } = string.Empty;

	public bool RememberMe { get; set; }

	public string? ReturnUrl { get; set; }
}
