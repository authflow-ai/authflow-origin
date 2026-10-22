using Rail.Kernel.Primitives;

namespace Rail.Kernel.OriginProtocol;

/// <summary>
/// Claims object inside <c>v1;&lt;claims&gt;;&lt;signature&gt;</c>. Member names and types are
/// protocol — adding or removing one is a version bump, not a silent JSON evolution.
/// </summary>
public sealed record OriginIdentityClaims
{
    public required string Issuer { get; init; }

    public required string KeyId { get; init; }

    public required UserId Subject { get; init; }

    public required ResourceUri Resource { get; init; }

    public required string Tier { get; init; }

    public required long IssuedAtUnix { get; init; }

    public required long ExpiresAtUnix { get; init; }

    public required string Nonce { get; init; }
}
