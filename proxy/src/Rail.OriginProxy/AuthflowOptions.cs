using System.ComponentModel.DataAnnotations;

namespace Rail.OriginProxy;

/// <summary>Configured constants for §4 verification and upstream forward.</summary>
public sealed class AuthflowOptions
{
    public const string SectionName = "Authflow";

    /// <summary>Origin Protocol issuer, e.g. <c>https://rails.authflow.ai</c>. No trailing slash.</summary>
    [Required]
    public string Issuer { get; set; } = "";

    /// <summary>Canonical resource URI this proxy guards, byte-for-byte.</summary>
    [Required]
    public string Resource { get; set; } = "";

    /// <summary>Base URI of the upstream MCP HTTP server. Path and query are preserved on forward.</summary>
    [Required]
    public string UpstreamBaseUri { get; set; } = "";

    /// <summary>
    /// Redis connection string for the shared nonce replay cache. Without it the replay check is
    /// process-local, and with more than one replica a replayed identity header that lands on a
    /// different replica is accepted, so the proxy refuses to start without it unless
    /// <see cref="SingleReplica"/> is set.
    /// </summary>
    public string? NonceCacheRedis { get; set; }

    /// <summary>
    /// The operator's declaration that exactly one replica of this proxy runs, which makes the
    /// process-local nonce replay cache safe. Required when <see cref="NonceCacheRedis"/> is unset;
    /// ignored when it is set.
    /// </summary>
    public bool SingleReplica { get; set; }
}
