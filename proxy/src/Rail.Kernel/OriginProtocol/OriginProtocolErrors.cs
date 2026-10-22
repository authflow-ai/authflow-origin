namespace Rail.Kernel.OriginProtocol;

/// <summary>
/// Origin Protocol v1 wire error codes. Published contract: version, never mutate.
/// </summary>
/// <remarks>
/// These strings are what a tenant's error handling switches on, and what the Phase 4 conformance
/// suite asserts. Before they lived here they were restated in the gateway's probe, the usage
/// endpoint and the sidecar proxy, which is how a probe and an origin come to disagree about the same
/// rejection. Every Rail implementation, the published proxy image included, now reads them from here.
/// </remarks>
public static class OriginProtocolErrors
{
    /// <summary>The §6.2 envelope's <c>error</c> member. Always this value on an identity rejection.</summary>
    public const string InvalidOriginIdentity = "invalid_origin_identity";

    // §6.1 reject conditions.
    public const string MissingIdentity = "missing_identity";
    public const string UnsupportedVersion = "unsupported_version";
    public const string MalformedIdentity = "malformed_identity";
    public const string BadSignature = "bad_signature";
    public const string UnknownKey = "unknown_key";
    public const string KeysUnavailable = "keys_unavailable";
    public const string Expired = "expired";
    public const string NotYetValid = "not_yet_valid";
    public const string ReplayedNonce = "replayed_nonce";
    public const string IssMismatch = "iss_mismatch";
    public const string ResourceMismatch = "resource_mismatch";
    public const string ForbiddenClaim = "forbidden_claim";

    /// <summary>
    /// Additive to §6.1: the replay store could not answer. Distinct from
    /// <see cref="ReplayedNonce"/> so a cache outage does not read as an attack in progress.
    /// </summary>
    public const string ReplayCacheUnavailable = "replay_cache_unavailable";

    /// <summary>
    /// §7 usage endpoint: the origin API key authenticated, but for a different resource than the
    /// one the reported usage names. Distinct from <see cref="ResourceMismatch"/>, which is an
    /// identity-header check on the origin.
    /// </summary>
    public const string OriginResourceMismatch = "origin_resource_mismatch";

    /// <summary>
    /// The development-only header mint refuses to run against a live origin key, so a production
    /// key can never be used to skip OAuth and Checkout.
    /// </summary>
    public const string LiveKeyForbidden = "live_key_forbidden";
}
