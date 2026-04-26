using AuthServer.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Repositories.Interfaces;

namespace PixSmith.Authorization.Repositories
{
	public class UserRepository : IUserRepository
	{
		private readonly ApplicationDbContext context;

		public UserRepository(ApplicationDbContext context)
		{
			this.context = context;
		}

		public async Task AddAsync(ApplicationUser user, CancellationToken ct = default)
		{
			// IdentityUser is created separately by UserManager in the API layer.
			// The repository owns the UserProfile, which holds profile data and IsActive.
			context.UserProfiles.Add(new UserProfile
			{
				Id = Guid.NewGuid(),
				UserId = user.Id,
				FirstName = user.FirstName,
				LastName = user.LastName,
				PhoneNumber = user.PhoneNumber,
				ProfilePictureUrl = user.ProfilePictureUrl,
				IsActive = user.IsActive,
				CreatedAt = user.CreatedAt,
				LastLoginAt = user.LastLoginAt,
			});

			await context.SaveChangesAsync(ct);
		}

		public async Task UpdateAsync(ApplicationUser user, CancellationToken ct = default)
		{
			// ── IdentityUser fields ──────────────────────────────────────────
			var identityUser = await context.Users.FindAsync([user.Id], ct);
			if (identityUser is not null)
			{
				identityUser.PasswordHash = user.PasswordHash;
				identityUser.EmailConfirmed = user.EmailConfirmed;
				identityUser.TwoFactorEnabled = user.TwoFactorEnabled;
				identityUser.AccessFailedCount = user.AccessFailedCount;
				// Map domain lockout to Identity lockout: non-null LockoutEnd when locked
				identityUser.LockoutEnabled = user.IsLocked;
				identityUser.LockoutEnd = user.IsLocked ? user.LockoutEnd : null;
			}

			// ── UserProfile fields ───────────────────────────────────────────
			var profile = await context.UserProfiles
				.FirstOrDefaultAsync(p => p.UserId == user.Id, ct);
			if (profile is not null)
			{
				profile.FirstName = user.FirstName;
				profile.LastName = user.LastName;
				profile.PhoneNumber = user.PhoneNumber;
				profile.ProfilePictureUrl = user.ProfilePictureUrl;
				profile.IsActive = user.IsActive;
				profile.LastLoginAt = user.LastLoginAt;
			}

			// ── Roles ────────────────────────────────────────────────────────
			var existingRoleNames = await (
				from ur in context.UserRoles
				join r in context.Roles on ur.RoleId equals r.Id
				where ur.UserId == user.Id
				select r.Name!
			).ToHashSetAsync(ct);

			var domainRoleNames = user.Roles.Select(r => r.Name).ToHashSet();

			// Remove roles dropped from the domain aggregate
			var roleRemoveList = await (
				from ur in context.UserRoles
				join r in context.Roles on ur.RoleId equals r.Id
				where ur.UserId == user.Id && !domainRoleNames.Contains(r.Name!)
				select ur
			).ToListAsync(ct);

			context.UserRoles.RemoveRange(roleRemoveList);

			// Add newly assigned roles
			foreach (var roleName in domainRoleNames.Except(existingRoleNames))
			{
				var role = await context.Roles.FirstOrDefaultAsync(r => r.Name == roleName, ct);
				if (role is not null)
					context.UserRoles.Add(new IdentityUserRole<Guid> { UserId = user.Id, RoleId = role.Id });
			}

			// ── External logins ──────────────────────────────────────────────
			var existingLogins = await context.UserLogins
				.Where(l => l.UserId == user.Id)
				.ToListAsync(ct);

			var existingLoginKeys = existingLogins
				.Select(l => (l.LoginProvider, l.ProviderKey))
				.ToHashSet();

			var domainLoginKeys = user.ExternalLogins
				.Select(el => (el.Provider, el.ProviderKey))
				.ToHashSet();

			// Remove logins no longer in the domain aggregate
			context.UserLogins.RemoveRange(
				existingLogins.Where(l => !domainLoginKeys.Contains((l.LoginProvider, l.ProviderKey))));

			// Add new external logins
			foreach (var el in user.ExternalLogins.Where(el => !existingLoginKeys.Contains((el.Provider, el.ProviderKey))))
			{
				context.UserLogins.Add(new IdentityUserLogin<Guid>
				{
					UserId = user.Id,
					LoginProvider = el.Provider,
					ProviderKey = el.ProviderKey,
					ProviderDisplayName = el.DisplayName,
				});
			}

			await context.SaveChangesAsync(ct);
		}

		public async Task DeleteAsync(Guid id, CancellationToken ct = default)
		{
			var identityUser = await context.Users.FindAsync([id], ct);
			if (identityUser is not null)
				context.Users.Remove(identityUser);

			var profile = await context.UserProfiles
				.FirstOrDefaultAsync(p => p.UserId == id, ct);
			if (profile is not null)
				context.UserProfiles.Remove(profile);

			await context.SaveChangesAsync(ct);
		}

		public async Task<ApplicationUser?> GetByIdAsync(Guid id, CancellationToken ct = default)
		{
			var identityUser = await context.Users.FindAsync([id], ct);
			return identityUser is null ? null : await MapAsync(identityUser, ct);
		}

		public async Task<ApplicationUser?> GetByEmailAsync(string email, CancellationToken ct = default)
		{
			var normalized = email.ToUpperInvariant();
			var identityUser = await context.Users
				.FirstOrDefaultAsync(u => u.NormalizedEmail == normalized, ct);
			return identityUser is null ? null : await MapAsync(identityUser, ct);
		}

		public async Task<ApplicationUser?> GetByUsernameAsync(string username, CancellationToken ct = default)
		{
			var normalized = username.ToUpperInvariant();
			var identityUser = await context.Users
				.FirstOrDefaultAsync(u => u.NormalizedUserName == normalized, ct);
			return identityUser is null ? null : await MapAsync(identityUser, ct);
		}

		public async Task<ApplicationUser?> GetByExternalLoginAsync(
			string provider, string providerKey, CancellationToken ct = default)
		{
			var login = await context.UserLogins
				.FirstOrDefaultAsync(l => l.LoginProvider == provider && l.ProviderKey == providerKey, ct);
			if (login is null) return null;

			var identityUser = await context.Users.FindAsync([login.UserId], ct);
			return identityUser is null ? null : await MapAsync(identityUser, ct);
		}

		public async Task<IEnumerable<ApplicationUser>> GetAllAsync(
			int page, int pageSize, CancellationToken ct = default)
		{
			var identityUsers = await context.Users
				.OrderBy(u => u.UserName)
				.Skip((page - 1) * pageSize)
				.Take(pageSize)
				.ToListAsync(ct);

			return await MapBatchAsync(identityUsers, ct);
		}

		public Task<int> CountAsync(CancellationToken ct = default) =>
			context.Users.CountAsync(ct);

		public async Task<IEnumerable<ApplicationUser>> SearchAsync(
			string query, CancellationToken ct = default)
		{
			var lower = query.ToLowerInvariant();
			var identityUsers = await context.Users
				.Where(u =>
					(u.UserName != null && u.UserName.ToLower().Contains(lower)) ||
					(u.Email != null && u.Email.ToLower().Contains(lower)))
				.Take(50)
				.ToListAsync(ct);

			return await MapBatchAsync(identityUsers, ct);
		}

		public async Task<bool> ExistsAsync(string email, CancellationToken ct = default)
		{
			var normalized = email.ToUpperInvariant();
			return await context.Users
				.AnyAsync(u => u.NormalizedEmail == normalized, ct);
		}

		// ── Mapping helpers ───────────────────────────────────────────────────

		private async Task<ApplicationUser> MapAsync(
			IdentityUser<Guid> identityUser, CancellationToken ct)
		{
			var profile = await context.UserProfiles
				.FirstOrDefaultAsync(p => p.UserId == identityUser.Id, ct);

			var roleNames = await (
				from ur in context.UserRoles
				join r in context.Roles on ur.RoleId equals r.Id
				where ur.UserId == identityUser.Id
				select r.Name!
			).ToListAsync(ct);

			var logins = await context.UserLogins
				.Where(l => l.UserId == identityUser.Id)
				.ToListAsync(ct);

			return Reconstitute(identityUser, profile, roleNames, logins);
		}

		private async Task<IEnumerable<ApplicationUser>> MapBatchAsync(
			IReadOnlyList<IdentityUser<Guid>> identityUsers, CancellationToken ct)
		{
			if (identityUsers.Count == 0) return [];

			var ids = identityUsers.Select(u => u.Id).ToList();

			var profiles = await context.UserProfiles
				.Where(p => ids.Contains(p.UserId))
				.ToListAsync(ct);

			var rolesByUser = await (
				from ur in context.UserRoles
				join r in context.Roles on ur.RoleId equals r.Id
				where ids.Contains(ur.UserId)
				select new { ur.UserId, RoleName = r.Name! }
			).ToListAsync(ct);

			var loginsByUser = await context.UserLogins
				.Where(l => ids.Contains(l.UserId))
				.ToListAsync(ct);

			return identityUsers.Select(u =>
			{
				var profile = profiles.FirstOrDefault(p => p.UserId == u.Id);
				var roles = rolesByUser.Where(r => r.UserId == u.Id).Select(r => r.RoleName);
				var logins = loginsByUser.Where(l => l.UserId == u.Id).ToList();
				return Reconstitute(u, profile, roles, logins);
			});
		}

		private static ApplicationUser Reconstitute(
			IdentityUser<Guid> u,
			UserProfile? profile,
			IEnumerable<string> roleNames,
			IEnumerable<IdentityUserLogin<Guid>> logins)
		{
			var isLocked = u.LockoutEnd.HasValue && u.LockoutEnd > DateTimeOffset.UtcNow;

			return ApplicationUser.Reconstitute(
				id: u.Id,
				username: u.UserName ?? string.Empty,
				email: u.Email ?? string.Empty,
				normalizedEmail: u.NormalizedEmail ?? string.Empty,
				passwordHash: u.PasswordHash,
				firstName: profile?.FirstName,
				lastName: profile?.LastName,
				phoneNumber: profile?.PhoneNumber,
				emailConfirmed: u.EmailConfirmed,
				twoFactorEnabled: u.TwoFactorEnabled,
				isActive: profile?.IsActive ?? true,
				isLocked: isLocked,
				lockoutEnd: u.LockoutEnd,
				accessFailedCount: u.AccessFailedCount,
				createdAt: profile?.CreatedAt ?? DateTimeOffset.UtcNow,
				lastLoginAt: profile?.LastLoginAt,
				profilePictureUrl: profile?.ProfilePictureUrl,
				roles: roleNames.Select(n => new UserRole(u.Id, n)),
				externalLogins: logins.Select(l =>
					new ExternalLoginProvider(l.LoginProvider, l.ProviderKey, l.ProviderDisplayName)));
		}
	}
}
