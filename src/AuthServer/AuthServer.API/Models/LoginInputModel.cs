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

	/// <summary>
	/// Display name of the company the calling application asked to sign in to, so the page
	/// can say which one rather than making the user work it out.
	///
	/// <para>
	/// Always the name stored against a real tenancy, never text echoed from the query string —
	/// otherwise a crafted link could make this page display any organisation it liked.
	/// </para>
	/// </summary>
	public string? OrganizationName { get; set; }
}
