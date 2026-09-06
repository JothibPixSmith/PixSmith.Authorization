using PixSmith.Authorization.Domain.Results;
using PixSmith.Authorization.DataContext;

namespace PixSmith.Authorization.Services.Interfaces;

public interface IAccountService
{
    Task<Result<UserDto>> RegisterAsync(RegisterUserRequest request, CancellationToken ct = default);
}
