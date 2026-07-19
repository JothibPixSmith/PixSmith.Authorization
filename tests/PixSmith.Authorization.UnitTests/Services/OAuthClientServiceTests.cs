using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Domain.Entities;
using PixSmith.Authorization.Domain.Enums;
using PixSmith.Authorization.Repositories.Interfaces;
using PixSmith.Authorization.Services;
using Xunit;

namespace PixSmith.Authorization.UnitTests.Services;

public sealed class OAuthClientServiceTests
{
    private readonly Mock<IOAuthClientRepository> repository = new();
    private readonly OAuthClientService sut;

    public OAuthClientServiceTests()
    {
        sut = new OAuthClientService(repository.Object, Mock.Of<ILogger<OAuthClientService>>());
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsFailure_WhenClientNotFound()
    {
        repository.Setup(r => r.GetByIdAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((OAuthClient?)null);

        var result = await sut.GetByIdAsync(Guid.NewGuid());

        result.IsSuccess.Should().BeFalse();
        result.Error.Should().Be("Client not found.");
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsMappedDto_WhenClientExists()
    {
        var client = OAuthClient.Create("client_abc", "secret", "My App", ClientType.Confidential, Guid.NewGuid());
        client.AddRedirectUri("https://app.local/callback");
        repository.Setup(r => r.GetByIdAsync(client.Id, It.IsAny<CancellationToken>())).ReturnsAsync(client);

        var result = await sut.GetByIdAsync(client.Id);

        result.IsSuccess.Should().BeTrue();
        result.Value!.DisplayName.Should().Be("My App");
        result.Value.RedirectUris.Should().ContainSingle().Which.Should().Be("https://app.local/callback");
    }

    [Fact]
    public async Task CreateAsync_PersistsClient_AndReturnsGeneratedCredentials()
    {
        var request = new CreateOAuthClientRequest(
            DisplayName: "New App",
            Description: null,
            ClientType: "Confidential",
            RedirectUris: ["https://app.local/callback"],
            AllowedScopes: ["api"],
            AllowedGrantTypes: ["authorization_code"]);

        OAuthClient? added = null;
        repository.Setup(r => r.AddAsync(It.IsAny<OAuthClient>(), It.IsAny<CancellationToken>()))
            .Callback<OAuthClient, CancellationToken>((c, _) => added = c)
            .Returns(Task.CompletedTask);

        var result = await sut.CreateAsync(request, createdByUserId: Guid.NewGuid());

        result.IsSuccess.Should().BeTrue();
        result.Value!.DisplayName.Should().Be("New App");
        result.Value.ClientSecret.Should().NotBeNullOrWhiteSpace();
        added.Should().NotBeNull();
        added!.RedirectUris.Should().Contain("https://app.local/callback");
        repository.Verify(r => r.AddAsync(It.IsAny<OAuthClient>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task DeactivateAsync_ReturnsFailure_WhenClientNotFound()
    {
        repository.Setup(r => r.GetByIdAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((OAuthClient?)null);

        var result = await sut.DeactivateAsync(Guid.NewGuid());

        result.IsSuccess.Should().BeFalse();
        repository.Verify(r => r.UpdateAsync(It.IsAny<OAuthClient>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task DeactivateAsync_UpdatesClient_WhenFound()
    {
        var client = OAuthClient.Create("client_abc", "secret", "My App", ClientType.Confidential, Guid.NewGuid());
        repository.Setup(r => r.GetByIdAsync(client.Id, It.IsAny<CancellationToken>())).ReturnsAsync(client);

        var result = await sut.DeactivateAsync(client.Id);

        result.IsSuccess.Should().BeTrue();
        client.IsActive.Should().BeFalse();
        repository.Verify(r => r.UpdateAsync(client, It.IsAny<CancellationToken>()), Times.Once);
    }
}
