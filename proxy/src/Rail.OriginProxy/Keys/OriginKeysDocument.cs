using System.Text.Json.Serialization;

namespace Rail.OriginProxy.Keys;

public sealed record OriginKeysDocumentDto
{
    [JsonPropertyName("issuer")]
    public string? Issuer { get; init; }

    [JsonPropertyName("protocol_version")]
    public string? ProtocolVersion { get; init; }

    [JsonPropertyName("keys")]
    public OriginPublicJwkDto[]? Keys { get; init; }
}

public sealed record OriginPublicJwkDto
{
    [JsonPropertyName("kty")]
    public string? KeyType { get; init; }

    [JsonPropertyName("crv")]
    public string? Curve { get; init; }

    [JsonPropertyName("kid")]
    public string? KeyId { get; init; }

    [JsonPropertyName("use")]
    public string? Use { get; init; }

    [JsonPropertyName("alg")]
    public string? Algorithm { get; init; }

    [JsonPropertyName("x")]
    public string? X { get; init; }

    [JsonPropertyName("d")]
    public string? D { get; init; }
}

/// <summary>Parsed v1-shaped public key ready for Ed25519 verify.</summary>
public sealed class OriginVerificationKey
{
    public required string KeyId { get; init; }

    public required byte[] PublicKeyRaw { get; init; }
}
