using AuthServer.Domain.Entities;
using PixSmith.Authorization.Repositories.Interfaces;
using System;
using System.Collections.Generic;
using System.Text;

namespace PixSmith.Authorization.Repositories
{
	public class UserRepository : IUserRepository
	{
		public Task AddAsync(ApplicationUser user, CancellationToken ct = default)
		{
			throw new NotImplementedException();
		}

		public Task<int> CountAsync(CancellationToken ct = default)
		{
			throw new NotImplementedException();
		}

		public Task DeleteAsync(Guid id, CancellationToken ct = default)
		{
			throw new NotImplementedException();
		}

		public Task<bool> ExistsAsync(string email, CancellationToken ct = default)
		{
			throw new NotImplementedException();
		}

		public Task<IEnumerable<ApplicationUser>> GetAllAsync(int page, int pageSize, CancellationToken ct = default)
		{
			throw new NotImplementedException();
		}

		public Task<ApplicationUser?> GetByEmailAsync(string email, CancellationToken ct = default)
		{
			throw new NotImplementedException();
		}

		public Task<ApplicationUser?> GetByExternalLoginAsync(string provider, string providerKey, CancellationToken ct = default)
		{
			throw new NotImplementedException();
		}

		public Task<ApplicationUser?> GetByIdAsync(Guid id, CancellationToken ct = default)
		{
			throw new NotImplementedException();
		}

		public Task<ApplicationUser?> GetByUsernameAsync(string username, CancellationToken ct = default)
		{
			throw new NotImplementedException();
		}

		public Task<IEnumerable<ApplicationUser>> SearchAsync(string query, CancellationToken ct = default)
		{
			throw new NotImplementedException();
		}

		public Task UpdateAsync(ApplicationUser user, CancellationToken ct = default)
		{
			throw new NotImplementedException();
		}
	}
}
