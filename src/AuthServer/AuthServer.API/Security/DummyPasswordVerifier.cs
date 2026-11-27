using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace PixSmith.Authorization.API.Security;

/// <summary>
/// Makes a failed sign-in cost the same whether or not the account exists.
///
/// <para>
/// The login form used to return as soon as the lookup found nobody, so only real accounts
/// paid for a PBKDF2 verification: measured at roughly 72 ms against 4 ms, with no overlap
/// between samples. That difference is an account-enumeration oracle as reliable as a
/// different error message, and it survives any wording change — which is why the generic
/// "Invalid email or password." is not on its own enough.
/// </para>
///
/// <para>
/// Every path that answers without verifying a password calls <see cref="Verify"/> instead:
/// no such account, and a locked-out account, which Identity refuses before it hashes
/// anything. The hash is computed once, over a random password nobody holds, with the same
/// <see cref="PasswordHasherOptions"/> Identity itself uses — so the work matches the real
/// path's rather than approximating it.
/// </para>
/// </summary>
public sealed class DummyPasswordVerifier
{
	private static readonly IdentityUser<Guid> Placeholder = new()
	{
		Id = Guid.Empty,
		UserName = "no-such-account",
		Email = "no-such-account@invalid",
	};

	private readonly PasswordHasher<IdentityUser<Guid>> hasher;
	private readonly string hash;

	public DummyPasswordVerifier(IOptions<PasswordHasherOptions> options)
	{
		// Identity registers IPasswordHasher<T> as scoped, so this cannot take it from DI and
		// stay a singleton. Building one from the same options is equivalent: the iteration
		// count, KDF and compatibility mode all come from there.
		this.hasher = new PasswordHasher<IdentityUser<Guid>>(options);

		// Random, and never stored anywhere: there is no password that verifies against this.
		this.hash = this.hasher.HashPassword(
			Placeholder, Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
	}

	private long invocations;

	/// <summary>
	/// How many times <see cref="Verify"/> has run. Exposed for the tests that pin this
	/// behaviour down; a timing assertion would be too flaky to keep.
	/// </summary>
	public long Invocations => Interlocked.Read(ref this.invocations);

	/// <summary>
	/// Performs the same password verification the real path performs, and discards the
	/// result. Always fails; the point is the time it takes.
	/// </summary>
	public void Verify(string? password)
	{
		Interlocked.Increment(ref this.invocations);

		// VerifyHashedPassword rejects a null password with an exception rather than a failure.
		this.hasher.VerifyHashedPassword(Placeholder, this.hash, password ?? string.Empty);
	}
}
