using AuthServer.Domain.Entities;
using AuthServer.Domain.Enums;
using AuthServer.Domain.Results;
using Microsoft.Extensions.Logging;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Repositories.Interfaces;
using PixSmith.Authorization.Services.Interfaces;

namespace PixSmith.Authorization.Services;


public sealed class OAuthClientService : IOAuthClientService
{
	private readonly ILogger<OAuthClientService> logger;
	private readonly IOAuthClientRepository repository;


	public OAuthClientService(IOAuthClientRepository repository,
	ILogger<OAuthClientService> logger)
	{
		this.repository = repository;
		this.logger = logger;
	}

	public async Task<Result<IEnumerable<OAuthClientDto>>> GetAllAsync(CancellationToken ct = default)
	{
		var clients = await this.repository.GetAllAsync(ct);
		return Result<IEnumerable<OAuthClientDto>>.Success(clients.Select(MapToDto));
	}

	public async Task<Result<OAuthClientDto>> GetByIdAsync(Guid id, CancellationToken ct = default)
	{
		var client = await repository.GetByIdAsync(id, ct);
		return client is null
			? Result<OAuthClientDto>.Failure("Client not found.")
			: Result<OAuthClientDto>.Success(MapToDto(client));
	}

	public async Task<Result<CreateOAuthClientResponse>> CreateAsync(
		CreateOAuthClientRequest request, Guid createdByUserId, CancellationToken ct = default)
	{
		var clientType = Enum.TryParse<ClientType>(request.ClientType, true, out var ct2)
			? ct2
			: ClientType.Confidential;

		var clientId = $"client_{Guid.NewGuid():N}"[..24];
		var clientSecret = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));

		var client = OAuthClient.Create(clientId, clientSecret, request.DisplayName, clientType, createdByUserId);

		if (request.Description is not null)
		{
			// description set via Update in real scenario; simplified here
		}

		foreach (var uri in request.RedirectUris) client.AddRedirectUri(uri);
		foreach (var scope in request.AllowedScopes) client.AddScope(scope);
		foreach (var grant in request.AllowedGrantTypes) client.AddGrantType(grant);

		await repository.AddAsync(client, ct);

		logger.LogInformation("Created OAuth client {ClientId} ({DisplayName})", clientId, request.DisplayName);

		return Result<CreateOAuthClientResponse>.Success(
			new CreateOAuthClientResponse(client.Id, clientId, clientSecret, request.DisplayName));
	}

	public async Task<Result> UpdateAsync(Guid id, UpdateOAuthClientRequest request, CancellationToken ct = default)
	{
		var client = await repository.GetByIdAsync(id, ct);
		if (client is null) return Result.Failure("Client not found");

		client.Update(request.DisplayName, request.Description, null,
			request.RequireConsent, request.AllowOfflineAccess,
			request.AccessTokenLifetimeSeconds, request.IdentityTokenLifetimeSeconds);

		await repository.UpdateAsync(client, ct);

		return Result.Success();
	}

	public async Task<Result> AddRedirectUriAsync(Guid id, string uri, CancellationToken ct = default)
	{
		var client = await repository.GetByIdAsync(id, ct);
		if (client is null) return Result.Failure("Client not found");
		client.AddRedirectUri(uri);
		await this.repository.UpdateAsync(client, ct);
		return Result.Success();
	}

	public async Task<Result> RemoveRedirectUriAsync(Guid id, string uri, CancellationToken ct = default)
	{
		var client = await repository.GetByIdAsync(id, ct);
		if (client is null) return Result.Failure("Client not found");
		client.RemoveRedirectUri(uri);
		await repository.UpdateAsync(client, ct);
		return Result.Success();
	}

	public async Task<Result> DeleteAsync(Guid id, CancellationToken ct = default)
	{
		await repository.DeleteAsync(id, ct);
		return Result.Success();
	}

	public async Task<Result> ActivateAsync(Guid id, CancellationToken ct = default)
	{
		var client = await repository.GetByIdAsync(id, ct);
		if (client is null) return Result.Failure("Client not found");
		client.Activate();
		await repository.UpdateAsync(client, ct);
		return Result.Success();
	}

	public async Task<Result> DeactivateAsync(Guid id, CancellationToken ct = default)
	{
		var client = await repository.GetByIdAsync(id, ct);
		if (client is null) return Result.Failure("Client not found");
		client.Deactivate();
		await repository.UpdateAsync(client, ct);
		return Result.Success();
	}

	private static OAuthClientDto MapToDto(OAuthClient c) => new(
		c.Id, c.ClientId, c.DisplayName, c.Description,
		c.ClientType.ToString(), c.IsActive, c.RequirePkce,
		c.AllowOfflineAccess, c.AccessTokenLifetimeSeconds,
		c.RedirectUris, c.AllowedScopes, c.AllowedGrantTypes, c.CreatedAt);
}
