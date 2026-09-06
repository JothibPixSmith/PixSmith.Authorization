using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Domain.Results;

namespace PixSmith.Authorization.Services.Interfaces;

public interface IOidcAppService
{
    Task<Result<IReadOnlyList<OidcAppDto>>> GetAllAsync(CancellationToken ct = default);
    Task<Result<OidcAppDto>> GetByClientIdAsync(string clientId, CancellationToken ct = default);
    Task<Result<OidcAppDto>> CreateAsync(CreateOidcAppRequest request, CancellationToken ct = default);
    Task<Result> UpdateAsync(string clientId, UpdateOidcAppRequest request, CancellationToken ct = default);
    Task<Result> DeleteAsync(string clientId, CancellationToken ct = default);
}
