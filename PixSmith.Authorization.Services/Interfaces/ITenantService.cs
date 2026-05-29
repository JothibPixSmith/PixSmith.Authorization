using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Domain.Results;

namespace PixSmith.Authorization.Services.Interfaces;

public interface ITenantService
{
    Task<Result<IEnumerable<TenantDto>>> GetAllAsync();
    Task<Result<TenantDto>> GetByIdAsync(Guid id);
    Task<Result<TenantDto>> CreateAsync(CreateTenantRequest request);
    Task<Result> UpdateAsync(Guid id, UpdateTenantRequest request);
    Task<Result> ActivateAsync(Guid id);
    Task<Result> DeactivateAsync(Guid id);
    Task<Result> DeleteAsync(Guid id);
}
