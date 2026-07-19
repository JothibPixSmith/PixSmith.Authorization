using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Repositories;
using Xunit;

namespace PixSmith.Authorization.IntegrationTests.Repositories;

/// <summary>
/// Exercises UserRepository against a real (SQLite, in-memory) database rather than mocks,
/// since its queries span Identity tables, UserProfile, UserRoles and UserLogins together.
/// </summary>
public sealed class UserRepositoryTests : IDisposable
{
    private readonly SqliteConnection connection;
    private readonly ApplicationDbContext context;
    private readonly UserRepository sut;

    public UserRepositoryTests()
    {
        connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();

        var optionsBuilder = new DbContextOptionsBuilder<ApplicationDbContext>();
        optionsBuilder.UseSqlite(connection);
        optionsBuilder.UseOpenIddict<Guid>();

        context = new ApplicationDbContext(optionsBuilder.Options);
        context.Database.EnsureCreated();

        sut = new UserRepository(context);
    }

    public void Dispose()
    {
        context.Dispose();
        connection.Dispose();
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsReconstitutedUser_WithProfileAndRoles()
    {
        var identityUser = new IdentityUser<Guid>
        {
            Id = Guid.NewGuid(),
            UserName = "jane.doe",
            NormalizedUserName = "JANE.DOE",
            Email = "jane.doe@example.com",
            NormalizedEmail = "JANE.DOE@EXAMPLE.COM",
            EmailConfirmed = true,
        };
        context.Users.Add(identityUser);

        var role = new IdentityRole<Guid> { Id = Guid.NewGuid(), Name = "User", NormalizedName = "USER" };
        context.Roles.Add(role);
        context.UserRoles.Add(new IdentityUserRole<Guid> { UserId = identityUser.Id, RoleId = role.Id });

        context.UserProfiles.Add(new UserProfile
        {
            Id = Guid.NewGuid(),
            UserId = identityUser.Id,
            FirstName = "Jane",
            LastName = "Doe",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
        });

        await context.SaveChangesAsync();

        var result = await sut.GetByIdAsync(identityUser.Id);

        result.Should().NotBeNull();
        result!.Email.Should().Be("jane.doe@example.com");
        result.FirstName.Should().Be("Jane");
        result.Roles.Select(r => r.Name).Should().Contain("User");
    }

    [Fact]
    public async Task ExistsAsync_ReturnsTrue_ForKnownEmail_CaseInsensitive()
    {
        context.Users.Add(new IdentityUser<Guid>
        {
            Id = Guid.NewGuid(),
            UserName = "bob",
            NormalizedUserName = "BOB",
            Email = "bob@example.com",
            NormalizedEmail = "BOB@EXAMPLE.COM",
        });
        await context.SaveChangesAsync();

        var exists = await sut.ExistsAsync("Bob@Example.com");

        exists.Should().BeTrue();
    }

    [Fact]
    public async Task ExistsAsync_ReturnsFalse_ForUnknownEmail()
    {
        var exists = await sut.ExistsAsync("nobody@example.com");

        exists.Should().BeFalse();
    }
}
