using Microsoft.Extensions.Options;
using Rail.Kernel.Primitives;

namespace Rail.OriginProxy;

/// <summary>
/// Refuses to start on an <c>Issuer</c> or <c>Resource</c> that can never match a header, and on a
/// replay cache that is not shared unless the operator declares a single replica.
/// </summary>
/// <remarks>
/// <para>
/// Both URIs are compared byte-for-byte with every identity header (§4 steps 11-12), and the rail
/// only ever issues the spelling <see cref="ResourceUri.Canonical"/> produces. Anything else is a
/// copy mistake that fails every request — and not always visibly: the key URL is built from a
/// trimmed issuer, so <c>https://rails.authflow.ai/</c> fetched keys without complaint, then
/// rejected the document's issuer and answered every call with <c>keys_unavailable</c>. The
/// configured string is never rewritten here, only checked.
/// </para>
/// <para>
/// A process-local nonce cache is correct on exactly one replica, and nothing tells a container how
/// many replicas run. Scaled out, the proxy would serve perfectly well until someone replays a
/// header against a replica that has not seen it, so without <c>Authflow:NonceCacheRedis</c> it
/// starts only when <c>Authflow:SingleReplica</c> says it runs alone.
/// </para>
/// </remarks>
internal sealed class AuthflowOptionsValidator : IValidateOptions<AuthflowOptions>
{
    /// <summary>The startup failure for a process-local cache nobody declared single-replica.</summary>
    public const string NoSharedNonceCache =
        "Authflow:NonceCacheRedis is not set, so replay protection would be process-local, which is only safe on a single replica. "
        + "Set Authflow:NonceCacheRedis (environment Authflow__NonceCacheRedis) to a Redis connection string to run any number of replicas, "
        + "or set Authflow:SingleReplica=true (environment Authflow__SingleReplica=true) to confirm this proxy runs as exactly one replica.";

    public ValidateOptionsResult Validate(string? name, AuthflowOptions options)
    {
        var failures = new List<string>(3);

        if (Problem(options.Issuer, isIssuer: true) is { } issuer)
        {
            failures.Add(Describe(nameof(options.Issuer), options.Issuer, issuer, "issuer", "https://rails.authflow.ai"));
        }

        if (Problem(options.Resource, isIssuer: false) is { } resource)
        {
            failures.Add(Describe(nameof(options.Resource), options.Resource, resource, "resource", "https://rails.authflow.ai/acme/mcp"));
        }

        if (string.IsNullOrWhiteSpace(options.NonceCacheRedis) && !options.SingleReplica)
        {
            failures.Add(NoSharedNonceCache);
        }

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    private static string? Problem(string? value, bool isIssuer)
    {
        // Absence is [Required]'s message to give, not a second one here.
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        if (!ResourceUri.TryCreate(value, out var canonical))
        {
            return "is not an absolute https URL (plain http only for a loopback host) without a query, fragment, or user information";
        }

        if (isIssuer && canonical.Value.AbsolutePath != "/")
        {
            return "must be a bare origin with no path";
        }

        if (value.EndsWith('/'))
        {
            return "must not end with '/'";
        }

        return string.Equals(value, canonical.Canonical, StringComparison.Ordinal)
            ? null
            : $"is not in canonical form; the canonical spelling is '{canonical.Canonical}'";
    }

    private static string Describe(string setting, string value, string problem, string receiptField, string example) =>
        $"{AuthflowOptions.SectionName}:{setting} '{Redact(value)}' {problem}. Copy the registration receipt's "
        + $"'{receiptField}' exactly (for example {example}): it is compared byte-for-byte with every identity header.";

    /// <summary>Startup errors end up in logs, so a password pasted into the URL is not repeated.</summary>
    private static string Redact(string value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.UserInfo.Length > 0
            ? $"{uri.Scheme}://***@{uri.Authority}{uri.PathAndQuery}{uri.Fragment}"
            : value;
}
