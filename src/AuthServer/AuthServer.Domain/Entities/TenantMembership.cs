namespace PixSmith.Authorization.Domain.Entities;

/// <summary>
/// A person's membership of a company (tenant), and the roles they hold there.
///
/// <para>
/// This is one half of the nested access model described in docs/MULTI-TENANCY.md. A user's
/// access to an application is <b>derived</b> from membership plus the company's subscription
/// to that application — it is never granted to the user directly.
/// </para>
///
/// <para>
/// Roles held here are scoped to this company only. Platform-level Identity roles are
/// deliberately separate and do not flow into a company context.
/// </para>
/// </summary>
public sealed class TenantMembership
{
    private readonly HashSet<string> _roles = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, HashSet<string>> _applicationRoles =
        new(StringComparer.OrdinalIgnoreCase);

    private TenantMembership() { }

    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public Guid UserId { get; private set; }
    public bool IsActive { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }

    /// <summary>Roles this member holds across the whole company.</summary>
    public IReadOnlyCollection<string> Roles => _roles;

    /// <summary>
    /// Roles this member holds only within a specific application, keyed by OIDC client id.
    /// Additive to <see cref="Roles"/>; it never removes company-wide roles.
    /// </summary>
    public IReadOnlyDictionary<string, IReadOnlyCollection<string>> ApplicationRoles =>
        _applicationRoles.ToDictionary(
            kvp => kvp.Key,
            kvp => (IReadOnlyCollection<string>)kvp.Value,
            StringComparer.OrdinalIgnoreCase);

    public static TenantMembership Create(Guid tenantId, Guid userId, IEnumerable<string>? roles = null)
    {
        if (tenantId == Guid.Empty) throw new ArgumentException("Tenant id is required.", nameof(tenantId));
        if (userId == Guid.Empty) throw new ArgumentException("User id is required.", nameof(userId));

        var membership = new TenantMembership
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            UserId = userId,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
        };

        foreach (var role in roles ?? [])
            membership.AssignRole(role);

        return membership;
    }

    public static TenantMembership Reconstitute(
        Guid id,
        Guid tenantId,
        Guid userId,
        bool isActive,
        DateTimeOffset createdAt,
        IEnumerable<string> roles,
        IEnumerable<(string ClientId, string Role)> applicationRoles)
    {
        var membership = new TenantMembership
        {
            Id = id,
            TenantId = tenantId,
            UserId = userId,
            IsActive = isActive,
            CreatedAt = createdAt,
        };

        foreach (var role in roles)
            membership._roles.Add(role);

        foreach (var (clientId, role) in applicationRoles)
            membership.ApplicationRoleSet(clientId).Add(role);

        return membership;
    }

    public void AssignRole(string role)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(role);
        _roles.Add(role.Trim());
    }

    public void RemoveRole(string role) => _roles.Remove(role?.Trim() ?? string.Empty);

    public void AssignApplicationRole(string clientId, string role)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentException.ThrowIfNullOrWhiteSpace(role);
        ApplicationRoleSet(clientId.Trim()).Add(role.Trim());
    }

    public void RemoveApplicationRole(string clientId, string role)
    {
        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(role)) return;
        if (_applicationRoles.TryGetValue(clientId.Trim(), out var set))
            set.Remove(role.Trim());
    }

    public void Activate() => IsActive = true;
    public void Deactivate() => IsActive = false;

    /// <summary>
    /// The flat role list for a token issued in this company for this application — the
    /// <c>roles</c> claim of RFC 9068. Company-wide roles are unioned with any roles scoped to
    /// this specific application, so a resource server reads one claim rather than reconciling
    /// several.
    /// </summary>
    public IReadOnlyCollection<string> EffectiveRoles(string? clientId)
    {
        var effective = new HashSet<string>(_roles, StringComparer.OrdinalIgnoreCase);

        if (!string.IsNullOrWhiteSpace(clientId)
            && _applicationRoles.TryGetValue(clientId.Trim(), out var scoped))
        {
            effective.UnionWith(scoped);
        }

        return effective;
    }

    private HashSet<string> ApplicationRoleSet(string clientId)
    {
        if (!_applicationRoles.TryGetValue(clientId, out var set))
        {
            set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _applicationRoles[clientId] = set;
        }
        return set;
    }
}
