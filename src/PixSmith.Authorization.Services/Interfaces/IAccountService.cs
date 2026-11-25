using PixSmith.Authorization.Domain.Results;
using PixSmith.Authorization.DataContext;

namespace PixSmith.Authorization.Services.Interfaces;

public interface IAccountService
{
    /// <summary>
    /// Registers a user. Succeeds with the same neutral response whether or not the email or
    /// username was already taken — see the implementation for why. Only input the caller can
    /// fix (mismatched or weak passwords) comes back as a failure.
    /// </summary>
    Task<Result<RegistrationAcceptedDto>> RegisterAsync(
        RegisterUserRequest request, CancellationToken ct = default);
}
