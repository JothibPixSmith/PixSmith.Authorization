using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Domain.Entities;
using PixSmith.Authorization.Domain.Results;
using PixSmith.Authorization.Repositories.Interfaces;
using PixSmith.Authorization.Services.Interfaces;

namespace PixSmith.Authorization.Services;

public sealed class TenantService(ITenantRepository repository) : ITenantService
{
    public async Task<Result<IEnumerable<TenantDto>>> GetAllAsync()
    {
        try
        {
            var tenants = await repository.GetAllAsync();
            return Result<IEnumerable<TenantDto>>.Success(tenants.Select(ToDto));
        }
        catch (Exception ex)
        {
            return Result<IEnumerable<TenantDto>>.Failure(ex.Message);
        }
    }

    public async Task<Result<TenantDto>> GetByIdAsync(Guid id)
    {
        var tenant = await repository.GetByIdAsync(id);
        return tenant is null
            ? Result<TenantDto>.Failure("Tenant not found.")
            : Result<TenantDto>.Success(ToDto(tenant));
    }

    public async Task<Result<TenantDto>> CreateAsync(CreateTenantRequest request)
    {
        try
        {
            var tenant = Tenant.Create(request.Name, request.Description);
            await repository.AddAsync(tenant);
            return Result<TenantDto>.Success(ToDto(tenant));
        }
        catch (Exception ex)
        {
            return Result<TenantDto>.Failure(ex.Message);
        }
    }

    public async Task<Result> UpdateAsync(Guid id, UpdateTenantRequest request)
    {
        var tenant = await repository.GetByIdAsync(id);
        if (tenant is null) return Result.Failure("Tenant not found.");

        try
        {
            tenant.Update(request.Name, request.Description);
            await repository.UpdateAsync(tenant);
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(ex.Message);
        }
    }

    public async Task<Result> ActivateAsync(Guid id)
    {
        var tenant = await repository.GetByIdAsync(id);
        if (tenant is null) return Result.Failure("Tenant not found.");
        tenant.Activate();
        await repository.UpdateAsync(tenant);
        return Result.Success();
    }

    public async Task<Result> DeactivateAsync(Guid id)
    {
        var tenant = await repository.GetByIdAsync(id);
        if (tenant is null) return Result.Failure("Tenant not found.");
        tenant.Deactivate();
        await repository.UpdateAsync(tenant);
        return Result.Success();
    }

    public async Task<Result> DeleteAsync(Guid id)
    {
        var tenant = await repository.GetByIdAsync(id);
        if (tenant is null) return Result.Failure("Tenant not found.");
        await repository.DeleteAsync(id);
        return Result.Success();
    }

    private static TenantDto ToDto(Tenant t) =>
        new(t.Id, t.Name, t.Slug, t.Description, t.IsActive, t.CreatedAt);
}
