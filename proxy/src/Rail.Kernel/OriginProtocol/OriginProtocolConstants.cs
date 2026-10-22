namespace Rail.Kernel.OriginProtocol;

/// <summary>
/// Wire constants for the Origin Protocol - the rail's only permitted coupling to a tenant
/// (ADR-005). These strings are a published contract: version, never mutate.
/// </summary>
public static class OriginProtocolConstants
{
    public const string IdentityHeaderName = "X-Authflow-Identity";

    /// <summary>
    /// Version prefix carried by every identity header. Origins MUST reject headers without a
    /// recognised prefix rather than fall through to anonymous access.
    /// </summary>
    public const string Version1 = "v1";

    /// <summary>Where origins fetch the rail's public keys to verify identity headers.</summary>
    public const string VerificationKeysPath = "/.well-known/authflow-origin-keys";

    /// <summary>Where origins report debit/credit events. Bound to one resource via the origin API key.</summary>
    public const string UsagePath = "/origin/v1/usage";

    /// <summary>
    /// Rail-hosted probe that posts deliberately valid and invalid identity headers at the
    /// registered origin so a tenant can verify §6.2 fail-closed behavior before cutover.
    /// </summary>
    public const string ConformancePath = "/origin/v1/conformance";

    /// <summary>
    /// Development-only: mint a signed identity header without the OAuth/Checkout loop.
    /// Mapped only when <c>OriginProtocol:EnableDevEndpoints</c> is true.
    /// </summary>
    public const string DevMintHeaderPath = "/origin/v1/dev/mint-header";

    /// <summary>Gateway-minted header TTL in seconds. Origins reject a TTL greater than 300.</summary>
    public const int HeaderTimeToLiveSeconds = 90;

    /// <summary>Clock-skew leeway applied when the rail validates a debit <c>identity_nonce</c>.</summary>
    public const int ClockSkewSeconds = 60;
}
