using PixSmith.Authorization.Domain.Results;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Services.Interfaces;

namespace PixSmith.Authorization.Services;

public sealed class AccountService(
    IUserService userService,
    PixSmith.Authorization.Repositories.Interfaces.IUserRepository userRepository,
    UserManager<IdentityUser<Guid>> userManager,
    IEmailService emailService,
    IConfiguration configuration,
    ILogger<AccountService> logger) : IAccountService
{
    /// <summary>
    /// The neutral answer. Returned byte-for-byte whether an account was created or the
    /// address already belonged to someone.
    /// </summary>
    private static readonly RegistrationAcceptedDto Accepted = new(
        "If the address can be registered, a confirmation email has been sent to it.");

    /// <summary>
    /// Identity's own codes for "this identity is taken". Matched on the code rather than the
    /// message so a localised or reworded description cannot slip the check.
    /// </summary>
    private static readonly string[] DuplicateCodes =
        ["DuplicateEmail", "DuplicateUserName"];

    public async Task<Result<RegistrationAcceptedDto>> RegisterAsync(
        RegisterUserRequest request, CancellationToken ct = default)
    {
        // Checked before anything else: it is the caller's own input and reveals nothing about
        // who else holds an account.
        if (request.Password != request.ConfirmPassword)
            return Result<RegistrationAcceptedDto>.Failure("Passwords do not match.");

        // ── Already taken? ───────────────────────────────────────────────────
        // Answer exactly as for a successful registration. Returning "that email is already
        // taken" to an anonymous caller turns this endpoint into an account oracle: an
        // attacker can confirm which addresses hold accounts and feed them to credential
        // stuffing or phishing. The real owner is told by email instead — they are the only
        // party entitled to know.

        var existingByEmail = await userManager.FindByEmailAsync(request.Email);
        var existingByName = await userManager.FindByNameAsync(request.Username);

        if (existingByEmail is not null || existingByName is not null)
        {
            logger.LogInformation(
                "Registration attempted for an address or username that already exists. " +
                "Answering neutrally. Email taken: {EmailTaken}, username taken: {NameTaken}.",
                existingByEmail is not null, existingByName is not null);

            // Only to the address that actually holds the account, and only when it is the
            // email that collided — notifying on a username collision would disclose the
            // attempt to somebody who may have no connection to it.
            if (existingByEmail?.Email is { Length: > 0 } ownerEmail)
                await emailService.SendRegistrationAttemptNoticeAsync(ownerEmail, SignInLink(), ct);

            return Result<RegistrationAcceptedDto>.Success(Accepted);
        }

        // ── Create ───────────────────────────────────────────────────────────

        var domainResult = await userService.RegisterAsync(request, ct);
        if (!domainResult.IsSuccess)
        {
            // The pre-check above handles the ordinary duplicate case; reaching here with a
            // duplicate means another request won a race between the check and the insert.
            // Answer neutrally for that too, so the race is not itself an oracle.
            if (LooksLikeDuplicate(domainResult.Error))
            {
                logger.LogInformation("Registration lost a race to a concurrent signup; answering neutrally.");
                return Result<RegistrationAcceptedDto>.Success(Accepted);
            }

            return Result<RegistrationAcceptedDto>.Failure(domainResult.Error!);
        }

        var dto = domainResult.Value!;

        var identityUser = new IdentityUser<Guid>
        {
            Id       = dto.Id,
            UserName = request.Username,
            Email    = request.Email,
        };

        var identityResult = await userManager.CreateAsync(identityUser, request.Password);
        if (!identityResult.Succeeded)
        {
            // Roll back the domain half. The UserProfile is written first and the IdentityUser
            // second, so a refusal here — a password the policy turns down, most often — would
            // otherwise leave a profile row with no account attached: invisible to every query
            // that starts from Identity, and never cleaned up. More likely now that the policy
            // asks for 12 characters and checks a breach list.
            await userRepository.DeleteAsync(dto.Id, ct);

            if (identityResult.Errors.Any(e => DuplicateCodes.Contains(e.Code, StringComparer.OrdinalIgnoreCase)))
            {
                logger.LogInformation(
                    "Identity reported a duplicate during registration; answering neutrally.");
                return Result<RegistrationAcceptedDto>.Success(Accepted);
            }

            // Everything else is the caller's own input — password policy, invalid email and
            // so on. Those say nothing about other accounts, and withholding them would leave
            // a user unable to work out why their password was refused.
            var error = string.Join("; ", identityResult.Errors.Select(e => e.Description));
            logger.LogWarning("Identity creation failed during registration: {Errors}", error);
            return Result<RegistrationAcceptedDto>.Failure(error);
        }

        await userManager.AddToRoleAsync(identityUser, "User");

        // Token requires the IdentityUser (security stamp) to exist, so this can only
        // happen here, after CreateAsync succeeds - not in UserService.RegisterAsync.
        var token = await userManager.GenerateEmailConfirmationTokenAsync(identityUser);
        var link = $"{BaseUri()}/confirm-email" +
                   $"?email={Uri.EscapeDataString(request.Email)}&token={Uri.EscapeDataString(token)}";
        await emailService.SendEmailConfirmationAsync(request.Email, link, ct);

        logger.LogInformation("Registered user {UserId}", dto.Id);
        return Result<RegistrationAcceptedDto>.Success(Accepted);
    }

    private static bool LooksLikeDuplicate(string? error) =>
        error is not null && error.Contains("already exists", StringComparison.OrdinalIgnoreCase);

    private string BaseUri() =>
        (configuration["OpenIddict:BlazorClient:BaseUri"] ?? string.Empty).TrimEnd('/');

    private string SignInLink() => $"{BaseUri()}/login";
}
