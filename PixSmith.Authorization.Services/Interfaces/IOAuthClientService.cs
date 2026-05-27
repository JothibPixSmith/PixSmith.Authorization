using PixSmith.Authorization.Domain.Results;
using PixSmith.Authorization.DataContext;

namespace PixSmith.Authorization.Services.Interfaces
{
	public interface IOAuthClientService
	{
		Task<Result<IEnumerable<OAuthClientDto>>> GetAllAsync(CancellationToken ct = default);
		Task<Result<OAuthClientDto>> GetByIdAsync(Guid id, CancellationToken ct = default);
		Task<Result<CreateOAuthClientResponse>> CreateAsync(CreateOAuthClientRequest request, Guid createdByUserId, CancellationToken ct = default);
		Task<Result> UpdateAsync(Guid id, UpdateOAuthClientRequest request, CancellationToken ct = default);
		Task<Result> AddRedirectUriAsync(Guid id, string uri, CancellationToken ct = default);
		Task<Result> RemoveRedirectUriAsync(Guid id, string uri, CancellationToken ct = default);
		Task<Result> DeleteAsync(Guid id, CancellationToken ct = default);
		Task<Result> ActivateAsync(Guid id, CancellationToken ct = default);
		Task<Result> DeactivateAsync(Guid id, CancellationToken ct = default);
	}
}
