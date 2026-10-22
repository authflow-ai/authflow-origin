namespace Rail.OriginProxy.Verification;

/// <summary>§4 accept: claims exposed for this HTTP request only.</summary>
public sealed record VerifiedOriginIdentity(
    string Subject,
    string Resource,
    string Tier,
    string Nonce,
    long IssuedAtUnix,
    long ExpiresAtUnix);
