namespace PixSmith.Authorization.Services.Interfaces;

/// <summary>
/// Writes durable audit entries for administrative actions.
///
/// <para>
/// The acting principal and client address are resolved from the ambient HTTP request rather
/// than passed in, so a caller cannot accidentally attribute an action to the wrong person —
/// and cannot omit the attribution at all.
/// </para>
/// </summary>
public interface IAuditService
{
    /// <summary>
    /// Records an action. Never throws: an audit-write failure must not turn a completed
    /// administrative action into an error response, because the caller would then believe it
    /// had not happened. Failures are logged at error level instead.
    /// </summary>
    /// <param name="action">Stable dotted identifier, e.g. <c>oidc-app.secret.rotated</c>.</param>
    /// <param name="details">
    /// Human-readable context. Never put secrets, tokens or passwords here — this table is read
    /// by anyone with admin access and is exactly the wrong place for credentials.
    /// </param>
    Task RecordAsync(string action, string? details = null, CancellationToken ct = default);
}
