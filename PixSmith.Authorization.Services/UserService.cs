using PixSmith.Authorization.Domain.Entities;
using PixSmith.Authorization.Domain.Results;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Repositories.Interfaces;
using PixSmith.Authorization.Services.Interfaces;

namespace PixSmith.Authorization.Services;

public interface IUserService
{
	Task<Result<UserDto>> RegisterAsync(RegisterUserRequest request, CancellationToken ct = default);
	Task<Result<UserDto>> GetByIdAsync(Guid id, CancellationToken ct = default);
	Task<Result<UserDto>> GetByEmailAsync(string email, CancellationToken ct = default);
	Task<Result<UserPagedResult>> GetAllAsync(int page = 1, int pageSize = 20, CancellationToken ct = default);
	Task<Result<UserDto>> UpdateProfileAsync(Guid userId, UpdateUserProfileRequest request, CancellationToken ct = default);
	Task<Result<UserDto>> AdminUpdateAsync(Guid userId, AdminUpdateUserRequest request, CancellationToken ct = default);
	Task<Result> ChangePasswordAsync(Guid userId, ChangePasswordRequest request, CancellationToken ct = default);
	Task<Result> ForgotPasswordAsync(ForgotPasswordRequest request, CancellationToken ct = default);
	Task<Result> ResetPasswordAsync(ResetPasswordRequest request, CancellationToken ct = default);
	Task<Result> ConfirmEmailAsync(string email, string token, CancellationToken ct = default);
	Task<Result> AssignRoleAsync(Guid userId, string role, CancellationToken ct = default);
	Task<Result> RemoveRoleAsync(Guid userId, string role, CancellationToken ct = default);
	Task<Result> DeactivateAsync(Guid userId, CancellationToken ct = default);
	Task<Result> ActivateAsync(Guid userId, CancellationToken ct = default);
	Task<Result> UnlockAsync(Guid userId, CancellationToken ct = default);
	Task<Result<UserDto>> FindOrCreateFromExternalLoginAsync(string provider, string providerKey,
		string email, string? firstName, string? lastName, CancellationToken ct = default);
}

public sealed class UserService : IUserService
{
	private readonly IUserRepository repository;
	private readonly IPasswordHashingService passwordHashingService;
	private readonly IEmailService emailService;
	private readonly UserManager<IdentityUser<Guid>> userManager;
	private readonly string frontendBaseUri;
	private readonly ILogger<UserService> logger;

	public UserService(
	IUserRepository repository,
	IPasswordHashingService passwordHashingService,
	IEmailService emailService,
	UserManager<IdentityUser<Guid>> userManager,
	IConfiguration configuration,
	ILogger<UserService> logger)
	{
		this.repository = repository;
		this.passwordHashingService = passwordHashingService;
		this.emailService = emailService;
		this.userManager = userManager;
		this.frontendBaseUri = (configuration["OpenIddict:BlazorClient:BaseUri"] ?? string.Empty).TrimEnd('/');
		this.logger = logger;
	}

	public async Task<Result<UserDto>> RegisterAsync(RegisterUserRequest request, CancellationToken ct = default)
	{
		if (await this.repository.ExistsAsync(request.Email, ct))
			return Result<UserDto>.Failure("A user with this email already exists.");

		if (request.Password != request.ConfirmPassword)
			return Result<UserDto>.Failure("Passwords do not match.");

		var user = ApplicationUser.Create(request.Username, request.Email, request.FirstName, request.LastName);
		user.SetPasswordHash(this.passwordHashingService.HashPassword(request.Password));
		user.AssignRole("User");

		await this.repository.AddAsync(user, ct);

		logger.LogInformation("New user registered: {Email}", request.Email);

		// The confirmation email is sent by AccountService once the IdentityUser (and its
		// password/security stamp, needed to generate a valid confirmation token) exists.

		return Result<UserDto>.Success(MapToDto(user));
	}

	public async Task<Result<UserDto>> GetByIdAsync(Guid id, CancellationToken ct = default)
	{
		var user = await this.repository.GetByIdAsync(id, ct);
		return user is null
			? Result<UserDto>.Failure("User not found.")
			: Result<UserDto>.Success(MapToDto(user));
	}

	public async Task<Result<UserDto>> GetByEmailAsync(string email, CancellationToken ct = default)
	{
		var user = await this.repository.GetByEmailAsync(email, ct);
		return user is null
			? Result<UserDto>.Failure("User not found.")
			: Result<UserDto>.Success(MapToDto(user));
	}

	public async Task<Result<UserPagedResult>> GetAllAsync(int page = 1, int pageSize = 20, CancellationToken ct = default)
	{
		var users = await this.repository.GetAllAsync(page, pageSize, ct);
		var total = await this.repository.CountAsync(ct);
		var dtos = users.Select(MapToDto).ToList();
		return Result<UserPagedResult>.Success(new UserPagedResult(dtos, total, page, pageSize));
	}

	public async Task<Result<UserDto>> UpdateProfileAsync(Guid userId, UpdateUserProfileRequest request, CancellationToken ct = default)
	{
		var user = await this.repository.GetByIdAsync(userId, ct);
		if (user is null) return Result<UserDto>.Failure("User not found.");

		user.UpdateProfile(request.FirstName, request.LastName, request.PhoneNumber, request.ProfilePictureUrl);
		await this.repository.UpdateAsync(user, ct);

		return Result<UserDto>.Success(MapToDto(user));
	}

	public async Task<Result<UserDto>> AdminUpdateAsync(Guid userId, AdminUpdateUserRequest request, CancellationToken ct = default)
	{
		var user = await this.repository.GetByIdAsync(userId, ct);
		if (user is null) return Result<UserDto>.Failure("User not found.");

		user.UpdateCoreFields(request.Username, request.Email, request.EmailConfirmed);
		user.UpdateProfile(request.FirstName, request.LastName, user.PhoneNumber, user.ProfilePictureUrl);
		await this.repository.UpdateAsync(user, ct);

		return Result<UserDto>.Success(MapToDto(user));
	}

	public async Task<Result> ChangePasswordAsync(Guid userId, ChangePasswordRequest request, CancellationToken ct = default)
	{
		var user = await this.repository.GetByIdAsync(userId, ct);
		if (user is null) return Result.Failure("User not found.");

		if (user.PasswordHash is null || !this.passwordHashingService.VerifyPassword(request.CurrentPassword, user.PasswordHash))
			return Result.Failure("Current password is incorrect.");

		if (request.NewPassword != request.ConfirmNewPassword)
			return Result.Failure("New passwords do not match.");

		user.SetPasswordHash(this.passwordHashingService.HashPassword(request.NewPassword));
		await this.repository.UpdateAsync(user, ct);

		return Result.Success();
	}

	public async Task<Result> ForgotPasswordAsync(ForgotPasswordRequest request, CancellationToken ct = default)
	{
		logger.LogInformation("Password reset requested for {Email}", request.Email);

		var identityUser = await this.userManager.FindByEmailAsync(request.Email);

		// Always return success regardless of outcome, to prevent email enumeration.
		if (identityUser is null || !await this.userManager.IsEmailConfirmedAsync(identityUser))
			return Result.Success();

		var token = await this.userManager.GeneratePasswordResetTokenAsync(identityUser);
		var link = $"{this.frontendBaseUri}/reset-password?email={Uri.EscapeDataString(request.Email)}&token={Uri.EscapeDataString(token)}";

		await this.emailService.SendPasswordResetAsync(request.Email, link, ct);

		return Result.Success();
	}

	public async Task<Result> ResetPasswordAsync(ResetPasswordRequest request, CancellationToken ct = default)
	{
		if (request.NewPassword != request.ConfirmNewPassword)
			return Result.Failure("Passwords do not match.");

		var identityUser = await this.userManager.FindByEmailAsync(request.Email);
		if (identityUser is null) return Result.Failure("Invalid or expired reset request.");

		var result = await this.userManager.ResetPasswordAsync(identityUser, request.Token, request.NewPassword);
		if (!result.Succeeded)
			return Result.Failure(string.Join("; ", result.Errors.Select(e => e.Description)));

		return Result.Success();
	}

	public async Task<Result> ConfirmEmailAsync(string email, string token, CancellationToken ct = default)
	{
		var identityUser = await this.userManager.FindByEmailAsync(email);
		if (identityUser is null) return Result.Failure("Invalid or expired confirmation link.");

		var result = await this.userManager.ConfirmEmailAsync(identityUser, token);
		return result.Succeeded
			? Result.Success()
			: Result.Failure("Invalid or expired confirmation link.");
	}

	public async Task<Result> AssignRoleAsync(Guid userId, string role, CancellationToken ct = default)
	{
		var user = await this.repository.GetByIdAsync(userId, ct);
		if (user is null) return Result.Failure("User not found.");

		user.AssignRole(role);
		await this.repository.UpdateAsync(user, ct);
		return Result.Success();
	}

	public async Task<Result> RemoveRoleAsync(Guid userId, string role, CancellationToken ct = default)
	{
		var user = await this.repository.GetByIdAsync(userId, ct);
		if (user is null) return Result.Failure("User not found.");

		user.RemoveRole(role);
		await this.repository.UpdateAsync(user, ct);
		return Result.Success();
	}

	public async Task<Result> DeactivateAsync(Guid userId, CancellationToken ct = default)
	{
		var user = await this.repository.GetByIdAsync(userId, ct);
		if (user is null) return Result.Failure("User not found.");

		user.Deactivate();
		await this.repository.UpdateAsync(user, ct);
		return Result.Success();
	}

	public async Task<Result> ActivateAsync(Guid userId, CancellationToken ct = default)
	{
		var user = await this.repository.GetByIdAsync(userId, ct);
		if (user is null) return Result.Failure("User not found.");

		user.Activate();
		await this.repository.UpdateAsync(user, ct);
		return Result.Success();
	}

	public async Task<Result> UnlockAsync(Guid userId, CancellationToken ct = default)
	{
		var user = await this.repository.GetByIdAsync(userId, ct);
		if (user is null) return Result.Failure("User not found.");

		user.Unlock();
		await this.repository.UpdateAsync(user, ct);
		return Result.Success();
	}

	public async Task<Result<UserDto>> FindOrCreateFromExternalLoginAsync(
		string provider, string providerKey, string email,
		string? firstName, string? lastName, CancellationToken ct = default)
	{
		// Try to find by external login first
		var user = await this.repository.GetByExternalLoginAsync(provider, providerKey, ct);
		if (user is not null) return Result<UserDto>.Success(MapToDto(user));

		// Fall back to email match
		user = await this.repository.GetByEmailAsync(email, ct);
		if (user is not null)
		{
			user.AddExternalLogin(provider, providerKey);
			await this.repository.UpdateAsync(user, ct);
			return Result<UserDto>.Success(MapToDto(user));
		}

		// Create new user from SSO
		var username = email.Split('@')[0] + "_" + provider.ToLower();
		user = ApplicationUser.Create(username, email, firstName, lastName);
		user.ConfirmEmail(); // SSO providers confirm email
		user.AddExternalLogin(provider, providerKey);
		user.AssignRole("User");

		await this.repository.AddAsync(user, ct);

		logger.LogInformation("Created user from external login {Provider}: {Email}", provider, email);
		return Result<UserDto>.Success(MapToDto(user));
	}

	// ─── Mapping ───────────────────────────────────────────────────────────

	private static UserDto MapToDto(ApplicationUser u) => new(
		u.Id, u.Username, u.Email, u.FirstName, u.LastName, u.FullName,
		u.EmailConfirmed, u.TwoFactorEnabled, u.IsActive, u.IsLocked,
		u.CreatedAt, u.LastLoginAt, u.ProfilePictureUrl,
		u.Roles.Select(r => r.Name).ToList().AsReadOnly());
}
