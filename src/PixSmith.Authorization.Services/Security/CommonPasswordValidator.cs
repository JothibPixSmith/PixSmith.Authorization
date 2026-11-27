using System.Reflection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace PixSmith.Authorization.Services.Security;

/// <summary>
/// Where the list of breached passwords comes from, and whether it is checked at all.
/// </summary>
public sealed class CommonPasswordOptions
{
    public const string SectionName = "Identity:Password:CommonPasswords";

    /// <summary>
    /// Whether to refuse passwords that appear on the list. On by default. Turning it off is
    /// a deliberate weakening: the composition rules that used to stand in for this check
    /// (a digit, an uppercase letter, a symbol) are off, because they produced
    /// <c>Password1!</c> rather than prevented it.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// A file to read instead of the embedded list — one password per line, <c>#</c> for
    /// comments. Use it to supply a larger list without rebuilding. If the file is missing or
    /// holds no entries, startup fails rather than silently falling back: a password check
    /// that quietly stops checking is worse than one that was never configured.
    /// </summary>
    public string? ListPath { get; set; }
}

/// <summary>
/// The set of passwords known to appear in credential breaches and attack dictionaries
/// (ASVS 6.2.4). Registered as a singleton: the list is read once and held in memory, because
/// it is consulted on every registration, password change and reset.
///
/// <para>
/// A password matches if the list holds it outright, or holds it with leading and trailing
/// punctuation removed. That second comparison is what catches the shape the old composition
/// rules encouraged — <c>Password1!</c> is not in any list as written, but <c>password1</c> is.
/// </para>
/// </summary>
public sealed class CommonPasswordList
{
    /// <summary>
    /// Set explicitly in the .csproj so renaming the folder cannot silently empty the list.
    /// </summary>
    public const string EmbeddedResourceName = "PixSmith.Authorization.Services.CommonPasswords.txt";

    private readonly HashSet<string> entries;

    public CommonPasswordList(IOptions<CommonPasswordOptions> options)
    {
        var value = options.Value;
        Enabled = value.Enabled;

        if (!Enabled)
        {
            this.entries = [];
            Source = "disabled";
            return;
        }

        var (lines, source) = Read(value.ListPath);
        Source = source;

        this.entries = new HashSet<string>(StringComparer.Ordinal);
        foreach (var line in lines)
        {
            var entry = line.Trim();
            if (entry.Length == 0 || entry[0] == '#') continue;
            this.entries.Add(entry.ToLowerInvariant());
        }

        // Fail closed. An empty list would validate every password as fine while looking
        // configured, which is the failure mode this check exists to prevent.
        if (this.entries.Count == 0)
        {
            throw new InvalidOperationException(
                $"The common-password list at {source} holds no entries. Supply a list with one "
                + $"password per line, or set {CommonPasswordOptions.SectionName}:Enabled to "
                + "false to accept breached passwords deliberately.");
        }
    }

    /// <summary>Whether the check is on at all.</summary>
    public bool Enabled { get; }

    /// <summary>Where the list was read from, for the startup log.</summary>
    public string Source { get; }

    public int Count => this.entries.Count;

    /// <summary>
    /// Whether this password is on the list, as written or stripped of its outer punctuation.
    /// </summary>
    public bool Contains(string? password)
    {
        if (!Enabled || string.IsNullOrEmpty(password)) return false;

        var lowered = password.ToLowerInvariant();
        if (this.entries.Contains(lowered)) return true;

        var stripped = StripOuterPunctuation(lowered);
        return stripped.Length > 0
            && !string.Equals(stripped, lowered, StringComparison.Ordinal)
            && this.entries.Contains(stripped);
    }

    /// <summary>
    /// Drops leading and trailing characters that are neither letters nor digits, so the
    /// decoration added to satisfy a composition rule does not hide the word underneath.
    /// </summary>
    public static string StripOuterPunctuation(string value)
    {
        var start = 0;
        var end = value.Length - 1;

        while (start <= end && !char.IsLetterOrDigit(value[start])) start++;
        while (end >= start && !char.IsLetterOrDigit(value[end])) end--;

        return start > end ? string.Empty : value[start..(end + 1)];
    }

    private static (IEnumerable<string> Lines, string Source) Read(string? path)
    {
        if (!string.IsNullOrWhiteSpace(path))
        {
            if (!File.Exists(path))
            {
                throw new InvalidOperationException(
                    $"{CommonPasswordOptions.SectionName}:ListPath points at '{path}', which "
                    + "does not exist.");
            }

            return (File.ReadLines(path), path);
        }

        var assembly = typeof(CommonPasswordList).GetTypeInfo().Assembly;
        var stream = assembly.GetManifestResourceStream(EmbeddedResourceName)
            ?? throw new InvalidOperationException(
                $"The embedded common-password list '{EmbeddedResourceName}' is missing from "
                + $"{assembly.GetName().Name}. Check the EmbeddedResource entry in the .csproj.");

        using var reader = new StreamReader(stream);
        return (reader.ReadToEnd().Split('\n'), $"embedded:{EmbeddedResourceName}");
    }
}

/// <summary>
/// Refuses passwords that appear on <see cref="CommonPasswordList"/>. Runs wherever Identity
/// validates a password — registration, change, reset and the admin seeder — because it is
/// registered as an <see cref="IPasswordValidator{TUser}"/> rather than called from a
/// controller.
///
/// <para>
/// The failure message talks only about the password, so it discloses nothing about accounts;
/// that is why password-policy errors can be reported in full on endpoints that otherwise
/// answer identically whether or not an account exists.
/// </para>
/// </summary>
public sealed class CommonPasswordValidator<TUser>(CommonPasswordList list)
    : IPasswordValidator<TUser>
    where TUser : class
{
    public const string ErrorCode = "PasswordIsCommon";

    public Task<IdentityResult> ValidateAsync(
        UserManager<TUser> manager, TUser user, string? password)
    {
        if (!list.Contains(password)) return Task.FromResult(IdentityResult.Success);

        return Task.FromResult(IdentityResult.Failed(new IdentityError
        {
            Code = ErrorCode,
            Description =
                "That password appears on lists of passwords exposed in data breaches, so it "
                + "is among the first an attacker tries. Choose something less predictable — "
                + "a passphrase of several unrelated words is both stronger and easier to "
                + "remember.",
        }));
    }
}
