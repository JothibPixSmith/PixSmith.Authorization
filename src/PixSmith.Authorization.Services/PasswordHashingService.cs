using Microsoft.AspNetCore.Identity;
using PixSmith.Authorization.Services.Interfaces;

namespace PixSmith.Authorization.Services;

/// <summary>
/// Bridges Domain's IPasswordHasher to ASP.NET Identity's PasswordHasher.
/// Infrastructure layer implements what Domain defines.
/// </summary>
public sealed class PasswordHashingService : IPasswordHashingService
{
    private readonly PasswordHasher<string> _hasher = new();

    public string HashPassword(string plaintext) =>
        _hasher.HashPassword(string.Empty, plaintext);

    public bool VerifyPassword(string plaintext, string hash) =>
        _hasher.VerifyHashedPassword(string.Empty, hash, plaintext)
            != PasswordVerificationResult.Failed;
}
