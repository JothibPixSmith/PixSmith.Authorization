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
        // The response deliberately carries nothing about the account — it is identical to
        // the one a already-registered address gets. See Register_IsIndistinguishable_*.
        var body = await response.Content.ReadAsStringAsync();
        body.Should().NotContain(request.Email);
        body.Should().NotContain(request.Username);
    }

    /// <summary>
    /// The anti-enumeration property: registering an address that already has an account must
    /// be indistinguishable from registering a fresh one. If these ever diverge — in status or
    /// body — the endpoint becomes an oracle for which addresses hold accounts.
    /// </summary>
    [Fact]
    public async Task Register_IsIndistinguishable_ForTakenAndFreshAddresses()
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

        // Same email, different username: only the address collides.
        var duplicate = await client.PostAsJsonAsync("/api/account/register", request with
        {
            Username = $"user_{Guid.NewGuid():N}",
        });

        // And a genuinely fresh registration, for comparison.
        var fresh = await client.PostAsJsonAsync("/api/account/register", new RegisterUserRequest(
            Username: $"user_{Guid.NewGuid():N}",
            Email: $"{Guid.NewGuid():N}@example.com",
            Password: "P@ssw0rd123",
            ConfirmPassword: "P@ssw0rd123",
            FirstName: "Test",
            LastName: "User"));

        duplicate.StatusCode.Should().Be(fresh.StatusCode);
        (await duplicate.Content.ReadAsStringAsync())
            .Should().Be(await fresh.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Register_StillReportsPolicyFailures()
    {
        // Withholding these would leave a user unable to see why their password was refused,
        // and they disclose nothing about anyone else's account.
        var response = await client.PostAsJsonAsync("/api/account/register", new RegisterUserRequest(
            Username: $"user_{Guid.NewGuid():N}",
            Email: $"{Guid.NewGuid():N}@example.com",
            Password: "weak",
            ConfirmPassword: "weak",
            FirstName: "Test",
            LastName: "User"));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Me_ReturnsUnauthorized_WithoutBearerToken()
    {
        var response = await client.GetAsync("/api/account/me");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }
}
