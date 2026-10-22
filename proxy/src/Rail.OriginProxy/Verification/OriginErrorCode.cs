using Rail.Kernel.OriginProtocol;

namespace Rail.OriginProxy.Verification;

/// <summary>§6.1 reject codes. Wire values are the enum names in snake_case via <see cref="ToWire"/>.</summary>
public enum OriginErrorCode
{
    MissingIdentity,
    UnsupportedVersion,
    MalformedIdentity,
    BadSignature,
    UnknownKey,
    KeysUnavailable,
    Expired,
    NotYetValid,
    ReplayedNonce,
    IssMismatch,
    ResourceMismatch,
    ForbiddenClaim,

    /// <summary>
    /// The replay cache could not be reached. Additive to §6.1: without it, a shared-cache outage
    /// would have to masquerade as <see cref="ReplayedNonce"/>, which sends an operator hunting a
    /// non-existent attack.
    /// </summary>
    ReplayCacheUnavailable
}

public static class OriginErrorCodeExtensions
{
    public static string ToWire(this OriginErrorCode code) => code switch
    {
        OriginErrorCode.MissingIdentity => OriginProtocolErrors.MissingIdentity,
        OriginErrorCode.UnsupportedVersion => OriginProtocolErrors.UnsupportedVersion,
        OriginErrorCode.MalformedIdentity => OriginProtocolErrors.MalformedIdentity,
        OriginErrorCode.BadSignature => OriginProtocolErrors.BadSignature,
        OriginErrorCode.UnknownKey => OriginProtocolErrors.UnknownKey,
        OriginErrorCode.KeysUnavailable => OriginProtocolErrors.KeysUnavailable,
        OriginErrorCode.Expired => OriginProtocolErrors.Expired,
        OriginErrorCode.NotYetValid => OriginProtocolErrors.NotYetValid,
        OriginErrorCode.ReplayedNonce => OriginProtocolErrors.ReplayedNonce,
        OriginErrorCode.IssMismatch => OriginProtocolErrors.IssMismatch,
        OriginErrorCode.ResourceMismatch => OriginProtocolErrors.ResourceMismatch,
        OriginErrorCode.ForbiddenClaim => OriginProtocolErrors.ForbiddenClaim,
        OriginErrorCode.ReplayCacheUnavailable => OriginProtocolErrors.ReplayCacheUnavailable,
        _ => OriginProtocolErrors.MalformedIdentity
    };

    public static string Description(this OriginErrorCode code) => code switch
    {
        OriginErrorCode.MissingIdentity =>
            "Request is missing a valid Authflow Origin Protocol identity header.",
        OriginErrorCode.UnsupportedVersion =>
            "Identity header protocol version is not supported.",
        OriginErrorCode.MalformedIdentity =>
            "Identity header is malformed.",
        OriginErrorCode.BadSignature =>
            "Identity header signature verification failed.",
        OriginErrorCode.UnknownKey =>
            "Identity header kid is not present in the issuer key document.",
        OriginErrorCode.KeysUnavailable =>
            "Origin Protocol verification keys are unavailable.",
        OriginErrorCode.Expired =>
            "Identity header has expired.",
        OriginErrorCode.NotYetValid =>
            "Identity header is not yet valid.",
        OriginErrorCode.ReplayedNonce =>
            "Identity header nonce has already been used.",
        OriginErrorCode.IssMismatch =>
            "Identity header issuer does not match this origin's configured issuer.",
        OriginErrorCode.ResourceMismatch =>
            "Identity header resource does not match this origin's configured resource.",
        OriginErrorCode.ForbiddenClaim =>
            "Identity header contains a forbidden credit-balance claim.",
        OriginErrorCode.ReplayCacheUnavailable =>
            "Replay protection is temporarily unavailable, so the request was refused.",
        _ => "Identity header was rejected."
    };
}
