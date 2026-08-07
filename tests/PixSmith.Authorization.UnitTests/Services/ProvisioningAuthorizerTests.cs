using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Services;
using PixSmith.Authorization.Services.Interfaces;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace PixSmith.Authorization.UnitTests.Services;

/// <summary>
/// These tests are the specification for the tenant-provisioning control. Each one encodes a
/// way an attacker could try to provision a tenancy without the required humans.
/// </summary>
public sealed class ProvisioningAuthorizerTests : IDisposable
{
    private readonly SqliteTestDb _db = new();

    private const string Method = "POST";
    private const string Path   = "/api/admin/tenants";
    private static readonly byte[] Body = "{\"name\":\"Acme\"}"u8.ToArray();

    // ── Happy path ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Quorum_of_distinct_keys_is_authorized()
    {
        var alice = new Operator("ops-alice");
        var bob   = new Operator("ops-bob");
        var sut   = Build(requiredSignatures: 2, alice, bob);

        var outcome = await sut.AuthorizeAsync(Attempt(alice, bob));

        Assert.True(outcome.Authorized);
        Assert.Equal(["ops-alice", "ops-bob"], outcome.SignedBy);
    }

    [Fact]
    public async Task Successful_request_records_the_signers_for_audit()
    {
        var alice = new Operator("ops-alice");
        var bob   = new Operator("ops-bob");
        var sut   = Build(requiredSignatures: 2, alice, bob);

        await sut.AuthorizeAsync(Attempt(alice, bob));

        var record = await _db.Context.ProvisioningNonces.SingleAsync();
        Assert.Equal("ops-alice,ops-bob", record.SignedBy);
        Assert.Equal("POST /api/admin/tenants", record.Operation);
    }

    // ── Quorum cannot be faked ────────────────────────────────────────────────

    [Fact]
    public async Task One_signature_does_not_satisfy_a_quorum_of_two()
    {
        var alice = new Operator("ops-alice");
        var bob   = new Operator("ops-bob");
        var sut   = Build(requiredSignatures: 2, alice, bob);

        var outcome = await sut.AuthorizeAsync(Attempt(alice));

        Assert.False(outcome.Authorized);
    }

    [Fact]
    public async Task Same_key_presented_twice_does_not_satisfy_a_quorum_of_two()
    {
        // The whole point of M-of-N is M distinct holders. A single compromised key that
        // could sign twice would collapse the control back to one party.
        var alice = new Operator("ops-alice");
        var bob   = new Operator("ops-bob");
        var sut   = Build(requiredSignatures: 2, alice, bob);

        var outcome = await sut.AuthorizeAsync(Attempt(alice, alice));

        Assert.False(outcome.Authorized);
    }

    [Fact]
    public async Task Key_that_is_not_enrolled_is_ignored()
    {
        var alice   = new Operator("ops-alice");
        var bob     = new Operator("ops-bob");
        var mallory = new Operator("ops-mallory");   // valid keypair, never enrolled
        var sut     = Build(requiredSignatures: 2, alice, bob);

        var outcome = await sut.AuthorizeAsync(Attempt(alice, mallory));

        Assert.False(outcome.Authorized);
    }

    [Fact]
    public async Task Signature_from_a_different_private_key_than_enrolled_is_rejected()
    {
        // Attacker knows an enrolled key ID and claims it, but holds a different private key.
        var alice    = new Operator("ops-alice");
        var bob      = new Operator("ops-bob");
        var imposter = new Operator("ops-alice");    // same ID, different keypair
        var sut      = Build(requiredSignatures: 2, alice, bob);

        var outcome = await sut.AuthorizeAsync(Attempt(imposter, bob));

        Assert.False(outcome.Authorized);
    }

    // ── The signature is bound to this exact request ──────────────────────────

    [Theory]
    [InlineData("DELETE", Path,                  "{\"name\":\"Acme\"}")]  // verb swapped
    [InlineData(Method,   "/api/admin/tenants/x", "{\"name\":\"Acme\"}")] // path swapped
    [InlineData(Method,   Path,                  "{\"name\":\"Evil\"}")]  // body swapped
    public async Task Signature_does_not_transfer_to_a_different_request(
        string method, string path, string body)
    {
        var alice = new Operator("ops-alice");
        var bob   = new Operator("ops-bob");
        var sut   = Build(requiredSignatures: 2, alice, bob);

        var signed = Attempt(alice, bob);
        var tampered = signed with
        {
            Method = method,
            Path   = path,
            Body   = Encoding.UTF8.GetBytes(body),
        };

        var outcome = await sut.AuthorizeAsync(tampered);

        Assert.False(outcome.Authorized);
    }

    // ── Replay ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Replaying_a_valid_request_is_rejected()
    {
        var alice = new Operator("ops-alice");
        var bob   = new Operator("ops-bob");
        var sut   = Build(requiredSignatures: 2, alice, bob);
        var attempt = Attempt(alice, bob);

        var first  = await sut.AuthorizeAsync(attempt);
        var second = await sut.AuthorizeAsync(attempt);

        Assert.True(first.Authorized);
        Assert.False(second.Authorized);
    }

    [Fact]
    public async Task Failed_attempt_does_not_burn_the_nonce()
    {
        // Otherwise anyone able to send one bad request could block the real operators
        // from using a nonce they had already coordinated on.
        var alice = new Operator("ops-alice");
        var bob   = new Operator("ops-bob");
        var sut   = Build(requiredSignatures: 2, alice, bob);

        const string nonce = "shared-nonce-value-1";

        var underSigned = Attempt(nonce, alice);
        var complete    = Attempt(nonce, alice, bob);

        Assert.False((await sut.AuthorizeAsync(underSigned)).Authorized);
        Assert.True((await sut.AuthorizeAsync(complete)).Authorized);
    }

    [Fact]
    public async Task Stale_timestamp_is_rejected()
    {
        var alice = new Operator("ops-alice");
        var bob   = new Operator("ops-bob");
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var sut   = Build(requiredSignatures: 2, clock, alice, bob);

        var attempt = Attempt(clock.GetUtcNow(), "nonce-for-stale-test1", alice, bob);
        clock.Advance(TimeSpan.FromMinutes(10));

        Assert.False((await sut.AuthorizeAsync(attempt)).Authorized);
    }

    // ── Fail closed ───────────────────────────────────────────────────────────

    [Fact]
    public async Task No_configured_keys_denies_everything()
    {
        var alice = new Operator("ops-alice");
        var sut   = Build(requiredSignatures: 2);   // trust anchor empty

        var outcome = await sut.AuthorizeAsync(Attempt(alice));

        Assert.False(outcome.Authorized);
    }

    [Fact]
    public async Task Fewer_enrolled_keys_than_the_threshold_denies_everything()
    {
        // A server configured to require two signatures but holding only one key must refuse,
        // not silently degrade to single-signature provisioning.
        var alice = new Operator("ops-alice");
        var sut   = Build(requiredSignatures: 2, alice);

        Assert.False((await sut.AuthorizeAsync(Attempt(alice))).Authorized);
    }

    [Fact]
    public async Task Threshold_below_one_denies_everything()
    {
        // Guards against "RequiredSignatures: 0" being used as an off switch.
        var alice = new Operator("ops-alice");
        var bob   = new Operator("ops-bob");
        var sut   = Build(requiredSignatures: 0, alice, bob);

        Assert.False((await sut.AuthorizeAsync(Attempt(alice, bob))).Authorized);
    }

    [Fact]
    public async Task Disabled_key_no_longer_counts()
    {
        var alice = new Operator("ops-alice");
        var bob   = new Operator("ops-bob");
        var carol = new Operator("ops-carol");

        var options = new TenantProvisioningOptions { RequiredSignatures = 2 };
        options.Keys.Add(alice.ToConfig(disabled: true));
        options.Keys.Add(bob.ToConfig());
        options.Keys.Add(carol.ToConfig());

        var sut = Build(options, new FakeTimeProvider(DateTimeOffset.UtcNow));

        Assert.False((await sut.AuthorizeAsync(Attempt(alice, bob))).Authorized);
        Assert.True((await sut.AuthorizeAsync(Attempt("nonce-carol-and-bob-1", bob, carol))).Authorized);
    }

    [Fact]
    public async Task Expired_key_no_longer_counts()
    {
        var alice = new Operator("ops-alice");
        var bob   = new Operator("ops-bob");
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);

        var options = new TenantProvisioningOptions { RequiredSignatures = 2 };
        options.Keys.Add(alice.ToConfig() with { NotAfter = clock.GetUtcNow().AddDays(-1) });
        options.Keys.Add(bob.ToConfig());

        var sut = Build(options, clock);

        Assert.False((await sut.AuthorizeAsync(Attempt(alice, bob))).Authorized);
    }

    [Fact]
    public async Task Malformed_nonce_is_rejected()
    {
        // A nonce containing a newline could otherwise splice extra fields into the
        // canonical payload.
        var alice = new Operator("ops-alice");
        var bob   = new Operator("ops-bob");
        var sut   = Build(requiredSignatures: 2, alice, bob);

        var outcome = await sut.AuthorizeAsync(Attempt("short\nbad", alice, bob));

        Assert.False(outcome.Authorized);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private ProvisioningAuthorizer Build(int requiredSignatures, params Operator[] enrolled) =>
        Build(requiredSignatures, new FakeTimeProvider(DateTimeOffset.UtcNow), enrolled);

    private ProvisioningAuthorizer Build(
        int requiredSignatures, TimeProvider clock, params Operator[] enrolled)
    {
        var options = new TenantProvisioningOptions { RequiredSignatures = requiredSignatures };
        foreach (var op in enrolled)
            options.Keys.Add(op.ToConfig());

        return Build(options, clock);
    }

    private ProvisioningAuthorizer Build(TenantProvisioningOptions options, TimeProvider clock) =>
        new(_db.Context, Options.Create(options), clock,
            NullLogger<ProvisioningAuthorizer>.Instance);

    private static ProvisioningAttempt Attempt(params Operator[] signers) =>
        Attempt($"nonce-{Guid.NewGuid():N}", signers);

    private static ProvisioningAttempt Attempt(string nonce, params Operator[] signers) =>
        Attempt(DateTimeOffset.UtcNow, nonce, signers);

    private static ProvisioningAttempt Attempt(
        DateTimeOffset signedAt, string nonce, params Operator[] signers)
    {
        var timestamp = signedAt.ToUnixTimeSeconds();
        var payload = ProvisioningSignature.BuildPayload(Method, Path, nonce, timestamp, Body);

        return new ProvisioningAttempt(
            Method, Path, nonce, timestamp.ToString(),
            [.. signers.Select(s => s.Sign(payload))],
            Body, Guid.NewGuid());
    }

    public void Dispose() => _db.Dispose();

    /// <summary>An operator holding a private key that never reaches the server.</summary>
    private sealed class Operator(string keyId)
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public string Sign(string payload)
        {
            var signature = _key.SignData(
                Encoding.UTF8.GetBytes(payload), HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);

            return $"{keyId}:{Convert.ToBase64String(signature)}";
        }

        public ProvisioningKey ToConfig(bool disabled = false) => new()
        {
            KeyId     = keyId,
            Holder    = keyId,
            PublicKey = Convert.ToBase64String(_key.ExportSubjectPublicKeyInfo()),
            Disabled  = disabled,
        };
    }
}

/// <summary>A real SQLite database so the unique-index replay defence is genuinely exercised.</summary>
internal sealed class SqliteTestDb : IDisposable
{
    private readonly Microsoft.Data.Sqlite.SqliteConnection _connection;

    public ApplicationDbContext Context { get; }

    public SqliteTestDb()
    {
        _connection = new Microsoft.Data.Sqlite.SqliteConnection("DataSource=:memory:");
        _connection.Open();

        Context = new ApplicationDbContext(
            new DbContextOptionsBuilder<ApplicationDbContext>()
                .UseSqlite(_connection)
                .Options);

        Context.Database.EnsureCreated();
    }

    public void Dispose()
    {
        Context.Dispose();
        _connection.Dispose();
    }
}
