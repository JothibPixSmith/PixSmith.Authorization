using AuthServer.Domain.Entities;
using PixSmith.Authorization.Repositories.Interfaces;
using System;
using System.Collections.Generic;
using System.Text;

namespace PixSmith.Authorization.Repositories
{
	public class OAuthClientRepository : IOAuthClientRepository
	{
		public Task AddAsync(OAuthClient client, CancellationToken ct = default)
		{
			throw new NotImplementedException();
		}

		public Task DeleteAsync(Guid id, CancellationToken ct = default)
		{
			throw new NotImplementedException();
		}

		public Task<IEnumerable<OAuthClient>> GetAllAsync(CancellationToken ct = default)
		{
			throw new NotImplementedException();
		}

		public Task<OAuthClient?> GetByClientIdAsync(string clientId, CancellationToken ct = default)
		{
			throw new NotImplementedException();
		}

		public Task<OAuthClient?> GetByIdAsync(Guid id, CancellationToken ct = default)
		{
			throw new NotImplementedException();
		}

		public Task UpdateAsync(OAuthClient client, CancellationToken ct = default)
		{
			throw new NotImplementedException();
		}
	}
}
