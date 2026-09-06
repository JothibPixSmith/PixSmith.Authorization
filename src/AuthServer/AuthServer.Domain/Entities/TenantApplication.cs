namespace PixSmith.Authorization.Domain.Entities;

/// <summary>
/// A company's subscription to an application.
///
/// <para>
/// The other half of the nested access model: a member may use an application if — and only if —
/// their company subscribes to it. Cancelling a subscription therefore removes access for every
/// member at once, without touching a single membership row.
/// </para>
/// </summary>
public sealed class TenantApplication
{
    private TenantApplication() { }

    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }

    /// <summary>
    /// The OpenIddict client identifier, held by value rather than as a foreign key.
    /// OpenIddict owns its own tables; referencing them by value keeps this schema independent
    /// of its migrations.
    /// </summary>
    public string ClientId { get; private set; } = string.Empty;

    public bool IsActive { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }

    public static TenantApplication Create(Guid tenantId, string clientId)
    {
        if (tenantId == Guid.Empty) throw new ArgumentException("Tenant id is required.", nameof(tenantId));
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);

        return new TenantApplication
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            ClientId = clientId.Trim(),
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
        };
    }

    public static TenantApplication Reconstitute(
        Guid id, Guid tenantId, string clientId, bool isActive, DateTimeOffset createdAt) =>
        new()
        {
            Id = id,
            TenantId = tenantId,
            ClientId = clientId,
            IsActive = isActive,
            CreatedAt = createdAt,
        };

    public void Activate() => IsActive = true;
    public void Deactivate() => IsActive = false;
}
