using System.Diagnostics.CodeAnalysis;

namespace Rail.Kernel.Primitives;

/// <summary>
/// A canonical, absolute resource identifier - the single most load-bearing string in the rail.
/// It is the resource's identity, fixed at first go-live (ADR-014): half of every
/// <see cref="Entitlements.EntitlementKey"/>, the Stripe <c>ResourceCanonical</c> stamp, the client
/// approval, nonce and rate-limit key, and the Origin Protocol <c>resource</c> claim.
/// </summary>
/// <remarks>
/// <para>
/// What a client sends (the RFC 8707 <c>resource</c> parameter, the URL it connects to) is a
/// <see cref="ResourceAddress"/>, a distinct type with no conversion to this one. Only the registry
/// turns an address into the identity it belongs to. Before first go-live a resource's single
/// address equals this value; afterwards this value never changes even when the primary address does.
/// </para>
/// <para>
/// Because it keys entitlements, canonicalisation must be total and stable: two spellings of the
/// same resource have to produce byte-identical <see cref="Canonical"/> strings, or a paying user
/// silently fails an entitlement lookup. Changing these rules invalidates issued tokens and stored
/// entitlements, so treat this type as a published format.
/// </para>
/// </remarks>
public sealed class ResourceUri : IEquatable<ResourceUri>
{
    private ResourceUri(Uri value, string canonical)
    {
        Value = value;
        Canonical = canonical;
    }

    public Uri Value { get; }

    /// <summary>The exact string persisted, signed, and compared. Never recompute it ad hoc.</summary>
    public string Canonical { get; }

    public static ResourceUri Create(string candidate) =>
        TryCreate(candidate, out var result)
            ? result
            : throw new ArgumentException($"'{candidate}' is not a valid resource URI.", nameof(candidate));

    /// <remarks>
    /// The rules (https or plaintext loopback; no query, fragment or userinfo; lowercase host; no
    /// trailing slash) live in <see cref="ResourceIdentifierForm"/>, shared with
    /// <see cref="ResourceAddress"/> so the two spell the same URL identically.
    /// </remarks>
    public static bool TryCreate(string? candidate, [NotNullWhen(true)] out ResourceUri? result)
    {
        result = null;
        if (!ResourceIdentifierForm.TryParse(candidate, out var uri, out var canonical))
        {
            return false;
        }

        result = new ResourceUri(uri, canonical);
        return true;
    }

    public bool Equals(ResourceUri? other) =>
        other is not null && string.Equals(Canonical, other.Canonical, StringComparison.Ordinal);

    public override bool Equals(object? obj) => Equals(obj as ResourceUri);

    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(Canonical);

    public override string ToString() => Canonical;
}
