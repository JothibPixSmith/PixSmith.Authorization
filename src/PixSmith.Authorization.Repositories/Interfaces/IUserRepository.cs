using PixSmith.Authorization.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Text;

namespace PixSmith.Authorization.Repositories.Interfaces
{
	public interface IUserRepository
	{
		Task<ApplicationUser?> GetByIdAsync(Guid id, CancellationToken ct = default);
		Task<ApplicationUser?> GetByEmailAsync(string email, CancellationToken ct = default);
		Task<ApplicationUser?> GetByUsernameAsync(string username, CancellationToken ct = default);
		Task<ApplicationUser?> GetByExternalLoginAsync(string provider, string providerKey, CancellationToken ct = default);
		Task<IEnumerable<ApplicationUser>> GetAllAsync(int page, int pageSize, CancellationToken ct = default);
		Task<int> CountAsync(CancellationToken ct = default);
		Task<IEnumerable<ApplicationUser>> SearchAsync(string query, CancellationToken ct = default);
		Task AddAsync(ApplicationUser user, CancellationToken ct = default);
		Task UpdateAsync(ApplicationUser user, CancellationToken ct = default);
		Task DeleteAsync(Guid id, CancellationToken ct = default);
		Task<bool> ExistsAsync(string email, CancellationToken ct = default);
	}
}
