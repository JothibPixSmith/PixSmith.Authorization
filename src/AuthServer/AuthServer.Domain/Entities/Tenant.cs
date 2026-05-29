namespace PixSmith.Authorization.Domain.Entities;

public sealed class Tenant
{
    private Tenant() { }

    public Guid Id { get; private set; }
    public string Name { get; private set; } = string.Empty;
    public string Slug { get; private set; } = string.Empty;
    public string? Description { get; private set; }
    public bool IsActive { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }

    public static Tenant Reconstitute(Guid id, string name, string slug, string? description, bool isActive, DateTimeOffset createdAt)
    {
        var tenant = new Tenant();
        tenant.Id = id;
        tenant.Name = name;
        tenant.Slug = slug;
        tenant.Description = description;
        tenant.IsActive = isActive;
        tenant.CreatedAt = createdAt;
        return tenant;
    }

    public static Tenant Create(string name, string? description)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        return new Tenant
        {
            Id = Guid.NewGuid(),
            Name = name.Trim(),
            Slug = GenerateSlug(name),
            Description = description?.Trim(),
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
        };
    }

    public void Update(string name, string? description)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        Name = name.Trim();
        Slug = GenerateSlug(name);
        Description = description?.Trim();
    }

    public void Activate() => IsActive = true;
    public void Deactivate() => IsActive = false;

    private static string GenerateSlug(string name) =>
        System.Text.RegularExpressions.Regex
            .Replace(name.Trim().ToLowerInvariant(), @"[^a-z0-9]+", "-")
            .Trim('-');
}
