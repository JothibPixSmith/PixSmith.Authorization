using AuthServer.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Text;

namespace PixSmith.Authorization.Repositories.Interfaces
{
	public interface IOAuthClientRepository
	{
		Task<OAuthClient?> GetByIdAsync(Guid id, CancellationToken ct = default);
		Task<OAuthClient?> GetByClientIdAsync(string clientId, CancellationToken ct = default);
		Task<IEnumerable<OAuthClient>> GetAllAsync(CancellationToken ct = default);
		Task AddAsync(OAuthClient client, CancellationToken ct = default);
		Task UpdateAsync(OAuthClient client, CancellationToken ct = default);
		Task DeleteAsync(Guid id, CancellationToken ct = default);
	}
}
