using OpenIddict.Abstractions;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Domain.Results;
using PixSmith.Authorization.Services.Interfaces;

namespace PixSmith.Authorization.Services;

public sealed class OidcScopeService(
    IOpenIddictScopeManager manager,
    IAuditService audit) : IOidcScopeService
{
    /// <summary>
    /// Scopes the server defines for itself. Renaming or re-pointing these would change the
    /// audience of tokens already deployed integrations validate, so they are read-only here.
    /// </summary>
    private static readonly string[] ReservedScopes =
        ["openid", "profile", "email", "roles", "offline_access", "api", "admin"];

    public async Task<Result<IReadOnlyList<OidcScopeDto>>> GetAllAsync(CancellationToken ct = default)
    {
        try
        {
            var scopes = new List<OidcScopeDto>();
            await foreach (var scope in manager.ListAsync(cancellationToken: ct))
                scopes.Add(await ToDtoAsync(scope, ct));

            return Result<IReadOnlyList<OidcScopeDto>>.Success(
                [.. scopes.OrderBy(s => s.Name, StringComparer.Ordinal)]);
        }
        catch (Exception ex)
        {
            return Result<IReadOnlyList<OidcScopeDto>>.Failure(ex.Message);
        }
    }

    public async Task<Result<OidcScopeDto>> GetByNameAsync(string name, CancellationToken ct = default)
    {
        var scope = await manager.FindByNameAsync(name, ct);
        return scope is null
            ? Result<OidcScopeDto>.Failure("Scope not found.")
            : Result<OidcScopeDto>.Success(await ToDtoAsync(scope, ct));
    }

    public async Task<Result<OidcScopeDto>> CreateAsync(
        CreateOidcScopeRequest request, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(request.Name))
            return Result<OidcScopeDto>.Failure("A scope name is required.");

        if (await manager.FindByNameAsync(request.Name, ct) is not null)
            return Result<OidcScopeDto>.Failure($"A scope named '{request.Name}' already exists.");

        // A scope with no resource produces tokens with no audience, which validating
        // resource servers reject — a confusing failure to debug from the client side.
        if (request.Resources is not { Count: > 0 } || request.Resources.All(string.IsNullOrWhiteSpace))
            return Result<OidcScopeDto>.Failure(
                "At least one resource is required — it becomes the 'aud' of tokens granted this scope.");

        try
        {
            var descriptor = new OpenIddictScopeDescriptor
            {
                Name = request.Name.Trim(),
                DisplayName = request.DisplayName,
                Description = request.Description,
            };

            foreach (var resource in request.Resources.Where(r => !string.IsNullOrWhiteSpace(r)))
                descriptor.Resources.Add(resource.Trim());

            var scope = await manager.CreateAsync(descriptor, ct);

            await audit.RecordAsync("oidc-scope.created",
                $"Scope '{descriptor.Name}' -> resources: {string.Join(", ", descriptor.Resources)}", ct);

            return Result<OidcScopeDto>.Success(await ToDtoAsync(scope, ct));
        }
        catch (Exception ex)
        {
            return Result<OidcScopeDto>.Failure(ex.Message);
        }
    }

    public async Task<Result> UpdateAsync(
        string name, UpdateOidcScopeRequest request, CancellationToken ct = default)
    {
        if (IsReserved(name))
            return Result.Failure(
                $"'{name}' is a built-in scope and cannot be modified. Changing its resources would " +
                "alter the audience of tokens that deployed integrations already validate.");

        var scope = await manager.FindByNameAsync(name, ct);
        if (scope is null) return Result.Failure("Scope not found.");

        if (request.Resources is not { Count: > 0 } || request.Resources.All(string.IsNullOrWhiteSpace))
            return Result.Failure("At least one resource is required.");

        try
        {
            var descriptor = new OpenIddictScopeDescriptor
            {
                Name = name,
                DisplayName = request.DisplayName,
                Description = request.Description,
            };

            foreach (var resource in request.Resources.Where(r => !string.IsNullOrWhiteSpace(r)))
                descriptor.Resources.Add(resource.Trim());

            await manager.UpdateAsync(scope, descriptor, ct);

            // Worth an audit row: this silently changes the `aud` of every future token
            // granted this scope, and a resource server validating the old value will start
            // rejecting them with no change on its own side.
            await audit.RecordAsync("oidc-scope.resources-changed",
                $"Scope '{name}' -> resources: {string.Join(", ", descriptor.Resources)}", ct);

            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(ex.Message);
        }
    }

    public async Task<Result> DeleteAsync(string name, CancellationToken ct = default)
    {
        if (IsReserved(name))
            return Result.Failure($"'{name}' is a built-in scope and cannot be deleted.");

        var scope = await manager.FindByNameAsync(name, ct);
        if (scope is null) return Result.Failure("Scope not found.");

        try
        {
            await manager.DeleteAsync(scope, ct);
            await audit.RecordAsync("oidc-scope.deleted", $"Scope '{name}'", ct);
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(ex.Message);
        }
    }

    private static bool IsReserved(string name) =>
        ReservedScopes.Contains(name, StringComparer.OrdinalIgnoreCase);

    private async Task<OidcScopeDto> ToDtoAsync(object scope, CancellationToken ct) => new(
        await manager.GetNameAsync(scope, ct) ?? string.Empty,
        await manager.GetDisplayNameAsync(scope, ct),
        await manager.GetDescriptionAsync(scope, ct),
        [.. await manager.GetResourcesAsync(scope, ct)]);
}
