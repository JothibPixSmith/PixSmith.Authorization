using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using PixSmith.Authorization.DataContext;
using Xunit;

namespace PixSmith.Authorization.IntegrationTests.Controllers;

public sealed class AccountControllerTests : IClassFixture<AuthWebApplicationFactory>
{
    private readonly HttpClient client;

    public AccountControllerTests(AuthWebApplicationFactory factory) =>
        client = factory.CreateClient();

    [Fact]
    public async Task Register_ReturnsOk_ForNewUser()
    {
        var request = new RegisterUserRequest(
            Username: $"user_{Guid.NewGuid():N}",
            Email: $"{Guid.NewGuid():N}@example.com",
            Password: "P@ssw0rd123",
            ConfirmPassword: "P@ssw0rd123",
            FirstName: "Test",
            LastName: "User");

        var response = await client.PostAsJsonAsync("/api/account/register", request);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var dto = await response.Content.ReadFromJsonAsync<UserDto>();
        dto.Should().NotBeNull();
        dto!.Email.Should().Be(request.Email);
    }

    [Fact]
    public async Task Register_ReturnsBadRequest_ForDuplicateEmail()
    {
        var request = new RegisterUserRequest(
            Username: $"user_{Guid.NewGuid():N}",
            Email: $"{Guid.NewGuid():N}@example.com",
            Password: "P@ssw0rd123",
            ConfirmPassword: "P@ssw0rd123",
            FirstName: "Test",
            LastName: "User");

        var first = await client.PostAsJsonAsync("/api/account/register", request);
        first.StatusCode.Should().Be(HttpStatusCode.OK);

        var duplicate = await client.PostAsJsonAsync("/api/account/register", request with
        {
            Username = $"user_{Guid.NewGuid():N}",
        });

        duplicate.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Me_ReturnsUnauthorized_WithoutBearerToken()
    {
        var response = await client.GetAsync("/api/account/me");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }
}
