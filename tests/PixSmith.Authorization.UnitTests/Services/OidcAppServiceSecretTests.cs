using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using OpenIddict.Abstractions;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Services;
using PixSmith.Authorization.Services.Interfaces;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace PixSmith.Authorization.UnitTests.Services;

/// <summary>
/// Client-secret handling on the OIDC application admin surface.
///
/// <para>
/// Regression cover for a real defect: <c>UpdateAsync</c> passed a null secret into the
/// descriptor, so OpenIddict refused every update of a confidential application with
/// "the client secret cannot be null or empty". Confidential clients could not be edited
/// at all.
/// </para>
/// </summary>
public sealed class OidcAppServiceSecretTests
{
    private readonly Mock<IOpenIddictApplicationManager> _manager = new();
    private readonly Mock<IAuditService> _audit = new();
    private readonly object _app = new();

    private OidcAppService Build() =>
        new(_manager.Object, _audit.Object, NullLogger<OidcAppService>.Instance);

    private void SeedApplication(string clientId, string clientType, string? storedSecret)
    {
        _manager.Setup(m => m.FindByClientIdAsync(clientId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(_app);
        _manager.Setup(m => m.GetClientTypeAsync(_app, It.IsAny<CancellationToken>()))
                .ReturnsAsync(clientType);

        // PopulateAsync fills the descriptor from the stored application — this is how the
        // service reads back the hashed secret it must preserve.
        _manager.Setup(m => m.PopulateAsync(
                    It.IsAny<OpenIddictApplicationDescriptor>(), _app, It.IsAny<CancellationToken>()))
                .Callback<OpenIddictApplicationDescriptor, object, CancellationToken>(
                    (descriptor, _, _) => descriptor.ClientSecret = storedSecret)
                .Returns(ValueTask.CompletedTask);
    }

    private static UpdateOidcAppRequest Update(string? name = "Renamed") =>
        new(name, [], [], ["api"], ["client_credentials"]);

    // ── The regression ────────────────────────────────────────────────────────

    [Fact]
    public async Task Updating_a_confidential_application_preserves_the_stored_secret()
    {
        SeedApplication("conf", ClientTypes.Confidential, "HASHED-SECRET");

        OpenIddictApplicationDescriptor? captured = null;
        _manager.Setup(m => m.UpdateAsync(_app, It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()))
                .Callback<object, OpenIddictApplicationDescriptor, CancellationToken>((_, d, _) => captured = d)
                .Returns(ValueTask.CompletedTask);

        var result = await Build().UpdateAsync("conf", Update());

        Assert.True(result.IsSuccess);
        // A null here is the bug: OpenIddict rejects the whole update for a confidential app.
        Assert.Equal("HASHED-SECRET", captured!.ClientSecret);
    }

    [Fact]
    public async Task Updating_a_public_application_keeps_its_secret_null()
    {
        // The inverse must also hold — OpenIddict rejects a secret on a public application.
        SeedApplication("pub", ClientTypes.Public, null);

        OpenIddictApplicationDescriptor? captured = null;
        _manager.Setup(m => m.UpdateAsync(_app, It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()))
                .Callback<object, OpenIddictApplicationDescriptor, CancellationToken>((_, d, _) => captured = d)
                .Returns(ValueTask.CompletedTask);

        Assert.True((await Build().UpdateAsync("pub", Update())).IsSuccess);
        Assert.Null(captured!.ClientSecret);
    }

    [Fact]
    public async Task Update_never_takes_the_secret_rotation_path()
    {
        // Editing metadata must not reach the overload that re-hashes and replaces the secret.
        SeedApplication("conf", ClientTypes.Confidential, "HASHED-SECRET");
        _manager.Setup(m => m.UpdateAsync(_app, It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()))
                .Returns(ValueTask.CompletedTask);

        await Build().UpdateAsync("conf", Update());

        _manager.Verify(m => m.UpdateAsync(_app, It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    // ── Rotation ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task Rotation_generates_a_strong_secret_when_none_is_supplied()
    {
        SeedApplication("conf", ClientTypes.Confidential, "HASHED-SECRET");
        _manager.Setup(m => m.UpdateAsync(_app, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(ValueTask.CompletedTask);

        var result = await Build().RotateSecretAsync("conf", new RotateClientSecretRequest(null));

        Assert.True(result.IsSuccess);
        // 32 random bytes, base64url, unpadded.
        Assert.Equal(43, result.Value!.ClientSecret.Length);
        Assert.DoesNotContain('+', result.Value.ClientSecret);
        Assert.DoesNotContain('/', result.Value.ClientSecret);
        Assert.DoesNotContain('=', result.Value.ClientSecret);
    }

    [Fact]
    public async Task Generated_secrets_are_not_repeated()
    {
        SeedApplication("conf", ClientTypes.Confidential, "HASHED-SECRET");
        _manager.Setup(m => m.UpdateAsync(_app, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(ValueTask.CompletedTask);

        var sut = Build();
        var first = (await sut.RotateSecretAsync("conf", new RotateClientSecretRequest(null))).Value!;
        var second = (await sut.RotateSecretAsync("conf", new RotateClientSecretRequest(null))).Value!;

        Assert.NotEqual(first.ClientSecret, second.ClientSecret);
    }

    [Fact]
    public async Task Rotation_uses_a_caller_supplied_secret_verbatim()
    {
        SeedApplication("conf", ClientTypes.Confidential, "HASHED-SECRET");

        string? persisted = null;
        _manager.Setup(m => m.UpdateAsync(_app, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Callback<object, string, CancellationToken>((_, s, _) => persisted = s)
                .Returns(ValueTask.CompletedTask);

        var result = await Build().RotateSecretAsync("conf", new RotateClientSecretRequest("chosen-secret"));

        Assert.Equal("chosen-secret", result.Value!.ClientSecret);
        Assert.Equal("chosen-secret", persisted);
    }

    [Fact]
    public async Task Rotating_a_public_application_is_refused_with_an_explanation()
    {
        SeedApplication("pub", ClientTypes.Public, null);

        var result = await Build().RotateSecretAsync("pub", new RotateClientSecretRequest(null));

        Assert.False(result.IsSuccess);
        Assert.Contains("no client secret to rotate", result.Error);
        _manager.Verify(m => m.UpdateAsync(_app, It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    // ── Audit ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_successful_rotation_is_audited()
    {
        SeedApplication("conf", ClientTypes.Confidential, "HASHED-SECRET");
        _manager.Setup(m => m.UpdateAsync(_app, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(ValueTask.CompletedTask);

        await Build().RotateSecretAsync("conf", new RotateClientSecretRequest(null));

        _audit.Verify(a => a.RecordAsync(
            "oidc-app.secret.rotated",
            It.Is<string>(d => d!.Contains("conf")),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task The_audit_entry_never_contains_the_secret()
    {
        // The audit table is readable by every admin — it is exactly the wrong place for a
        // credential, and a rotation is precisely when one is in scope.
        SeedApplication("conf", ClientTypes.Confidential, "HASHED-SECRET");
        _manager.Setup(m => m.UpdateAsync(_app, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(ValueTask.CompletedTask);

        string? recorded = null;
        _audit.Setup(a => a.RecordAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
              .Callback<string, string?, CancellationToken>((_, d, _) => recorded = d)
              .Returns(Task.CompletedTask);

        var result = await Build().RotateSecretAsync("conf", new RotateClientSecretRequest("super-secret-value"));

        Assert.Equal("super-secret-value", result.Value!.ClientSecret);
        Assert.NotNull(recorded);
        Assert.DoesNotContain("super-secret-value", recorded);
    }

    [Fact]
    public async Task A_refused_rotation_is_also_audited()
    {
        // A stream of refused attempts against public clients is a signal worth keeping.
        SeedApplication("pub", ClientTypes.Public, null);

        await Build().RotateSecretAsync("pub", new RotateClientSecretRequest(null));

        _audit.Verify(a => a.RecordAsync(
            "oidc-app.secret.rotation-refused", It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task Nothing_is_audited_when_the_rotation_itself_throws()
    {
        // An entry claiming a rotation that never happened is worse than a missing one.
        SeedApplication("conf", ClientTypes.Confidential, "HASHED-SECRET");
        _manager.Setup(m => m.UpdateAsync(_app, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new InvalidOperationException("store failure"));

        var result = await Build().RotateSecretAsync("conf", new RotateClientSecretRequest(null));

        Assert.False(result.IsSuccess);
        _audit.Verify(a => a.RecordAsync("oidc-app.secret.rotated", It.IsAny<string>(),
            It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task Rotating_an_unknown_application_fails()
    {
        _manager.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync((object?)null);

        var result = await Build().RotateSecretAsync("ghost", new RotateClientSecretRequest(null));

        Assert.False(result.IsSuccess);
        Assert.Contains("not found", result.Error);
    }

    [Fact]
    public async Task A_blank_supplied_secret_is_treated_as_generate()
    {
        // Otherwise an empty form field would silently clear the secret and break the client.
        SeedApplication("conf", ClientTypes.Confidential, "HASHED-SECRET");
        _manager.Setup(m => m.UpdateAsync(_app, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(ValueTask.CompletedTask);

        var result = await Build().RotateSecretAsync("conf", new RotateClientSecretRequest("   "));

        Assert.True(result.IsSuccess);
        Assert.Equal(43, result.Value!.ClientSecret.Length);
    }
}
