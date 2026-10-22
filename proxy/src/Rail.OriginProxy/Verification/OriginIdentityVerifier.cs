using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using NSec.Cryptography;
using Rail.Kernel.OriginProtocol;
using Rail.Kernel.Time;
using Rail.OriginProxy.Keys;
using Rail.OriginProxy.Nonce;

namespace Rail.OriginProxy.Verification;

/// <summary>Normative §4 verification algorithm against configured issuer/resource.</summary>
public sealed class OriginIdentityVerifier
{
    public static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(OriginProtocolConstants.ClockSkewSeconds);

    public const int MaxHeaderTtlSeconds = 300;

    private static readonly SignatureAlgorithm Ed25519 = SignatureAlgorithm.Ed25519;

    private static readonly HashSet<string> ForbiddenMembers = new(StringComparer.Ordinal)
    {
        "credits",
        "credit_balance",
        "balance",
        "remaining",
        "remaining_credits",
        "quota",
        "units_remaining"
    };

    private static readonly Regex KidPattern = new(
        "^[A-Za-z0-9._-]{1,64}\\z",
        RegexOptions.CultureInvariant | RegexOptions.Compiled,
        TimeSpan.FromSeconds(1));

    private static readonly Regex TierPattern = new(
        "^[a-z][a-z0-9_]{0,63}\\z",
        RegexOptions.CultureInvariant | RegexOptions.Compiled,
        TimeSpan.FromSeconds(1));

    private static readonly Regex NoncePattern = new(
        "^[A-Za-z0-9_-]{16,64}\\z",
        RegexOptions.CultureInvariant | RegexOptions.Compiled,
        TimeSpan.FromSeconds(1));

    private static readonly Regex LowerUuidPattern = new(
        "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\z",
        RegexOptions.CultureInvariant | RegexOptions.Compiled,
        TimeSpan.FromSeconds(1));

    private readonly AuthflowOptions _options;
    private readonly OriginKeyCache _keys;
    private readonly INonceReplayCache _nonces;
    private readonly IClock _clock;

    public OriginIdentityVerifier(
        IOptions<AuthflowOptions> options,
        OriginKeyCache keys,
        INonceReplayCache nonces,
        IClock clock)
    {
        _options = options.Value;
        _keys = keys;
        _nonces = nonces;
        _clock = clock;
    }

    public async Task<(VerifiedOriginIdentity? Identity, OriginErrorCode? Error)> VerifyAsync(
        IHeaderDictionary headers,
        CancellationToken cancellationToken)
    {
        // 1. Presence
        if (!headers.TryGetValue(OriginProtocolConstants.IdentityHeaderName, out var values) ||
            values.Count == 0 ||
            (values.Count == 1 && string.IsNullOrWhiteSpace(values[0])))
        {
            return Fail(OriginErrorCode.MissingIdentity);
        }

        if (values.Count > 1)
        {
            return Fail(OriginErrorCode.MissingIdentity);
        }

        var raw = values[0]!.Trim();
        if (raw.Length == 0)
        {
            return Fail(OriginErrorCode.MissingIdentity);
        }

        // 2. Split
        var parts = raw.Split(';');
        if (parts.Length != 3 ||
            parts[0].Length == 0 ||
            parts[1].Length == 0 ||
            parts[2].Length == 0)
        {
            return Fail(OriginErrorCode.MalformedIdentity);
        }

        // 3. Version
        if (!string.Equals(parts[0], OriginProtocolConstants.Version1, StringComparison.Ordinal))
        {
            return Fail(OriginErrorCode.UnsupportedVersion);
        }

        var claimsB64 = parts[1];
        var sigB64 = parts[2];

        // 4. Canonical base64url
        if (!Base64Url.TryDecode(claimsB64, out var claimsBytes) ||
            !Base64Url.TryDecode(sigB64, out var signatureBytes))
        {
            return Fail(OriginErrorCode.MalformedIdentity);
        }

        // 5. Decode signature length
        if (signatureBytes.Length != 64)
        {
            return Fail(OriginErrorCode.MalformedIdentity);
        }

        // 6. Decode claims JSON (UTF-8, reject BOM)
        if (claimsBytes.Length >= 3 &&
            claimsBytes[0] == 0xEF &&
            claimsBytes[1] == 0xBB &&
            claimsBytes[2] == 0xBF)
        {
            return Fail(OriginErrorCode.MalformedIdentity);
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(claimsBytes);
        }
        catch (JsonException)
        {
            return Fail(OriginErrorCode.MalformedIdentity);
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return Fail(OriginErrorCode.MalformedIdentity);
            }

            // 7. Read kid + key lookup (with one forced refresh)
            if (!root.TryGetProperty("kid", out var kidEl) || kidEl.ValueKind != JsonValueKind.String)
            {
                return Fail(OriginErrorCode.MalformedIdentity);
            }

            // Grammar before lookup: the header is not authenticated yet, so a kid no valid document
            // can contain must not be allowed to force a key fetch.
            var kid = kidEl.GetString();
            if (kid is null || !KidPattern.IsMatch(kid))
            {
                return Fail(OriginErrorCode.MalformedIdentity);
            }

            var lookup = await _keys.ResolveAsync(kid, cancellationToken);
            if (lookup.Status == KeyLookupStatus.Unavailable)
            {
                return Fail(OriginErrorCode.KeysUnavailable);
            }

            if (lookup.Status == KeyLookupStatus.Unknown || lookup.Key is null)
            {
                return Fail(OriginErrorCode.UnknownKey);
            }

            // 8. Verify signature
            var signingInput = OriginIdentityCompact.SigningInput(claimsB64);
            PublicKey publicKey;
            try
            {
                publicKey = PublicKey.Import(Ed25519, lookup.Key.PublicKeyRaw, KeyBlobFormat.RawPublicKey);
            }
            catch (FormatException)
            {
                return Fail(OriginErrorCode.KeysUnavailable);
            }

            if (!Ed25519.Verify(publicKey, signingInput, signatureBytes))
            {
                return Fail(OriginErrorCode.BadSignature);
            }

            // 9. Forbidden members (any nesting level)
            if (ContainsForbiddenMember(root))
            {
                return Fail(OriginErrorCode.ForbiddenClaim);
            }

            // 10. Required members and types
            if (!TryReadValidatedClaims(root, out var claims))
            {
                return Fail(OriginErrorCode.MalformedIdentity);
            }

            // 11. Issuer binding
            if (!string.Equals(claims.Issuer, _options.Issuer, StringComparison.Ordinal))
            {
                return Fail(OriginErrorCode.IssMismatch);
            }

            // 12. Resource binding (byte-for-byte; do not re-canonicalise)
            if (!string.Equals(claims.Resource, _options.Resource, StringComparison.Ordinal))
            {
                return Fail(OriginErrorCode.ResourceMismatch);
            }

            // 13. TTL shape
            if (claims.ExpiresAtUnix <= claims.IssuedAtUnix ||
                claims.ExpiresAtUnix - claims.IssuedAtUnix > MaxHeaderTtlSeconds)
            {
                return Fail(OriginErrorCode.MalformedIdentity);
            }

            var now = _clock.UtcNow.ToUnixTimeSeconds();
            var skew = (long)ClockSkew.TotalSeconds;

            // 14. Expiry
            if (now > claims.ExpiresAtUnix + skew)
            {
                return Fail(OriginErrorCode.Expired);
            }

            // 15. Not-yet-valid
            if (claims.IssuedAtUnix > now + skew)
            {
                return Fail(OriginErrorCode.NotYetValid);
            }

            // 16. Replay
            var retainUntil = DateTimeOffset.FromUnixTimeSeconds(claims.ExpiresAtUnix + skew);
            var recorded = await _nonces.TryRecordAsync(claims.Nonce, retainUntil, cancellationToken);
            if (recorded is not NonceRecordResult.Recorded)
            {
                return Fail(recorded is NonceRecordResult.Replay
                    ? OriginErrorCode.ReplayedNonce
                    : OriginErrorCode.ReplayCacheUnavailable);
            }

            // 17. Accept
            return (new VerifiedOriginIdentity(
                claims.Subject,
                claims.Resource,
                claims.Tier,
                claims.Nonce,
                claims.IssuedAtUnix,
                claims.ExpiresAtUnix), null);
        }
    }

    private static (VerifiedOriginIdentity? Identity, OriginErrorCode? Error) Fail(OriginErrorCode code) =>
        (null, code);

    private static bool ContainsForbiddenMember(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    if (ForbiddenMembers.Contains(property.Name))
                    {
                        return true;
                    }

                    if (ContainsForbiddenMember(property.Value))
                    {
                        return true;
                    }
                }

                return false;

            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    if (ContainsForbiddenMember(item))
                    {
                        return true;
                    }
                }

                return false;

            default:
                return false;
        }
    }

    private static bool TryReadValidatedClaims(JsonElement root, out RawClaims claims)
    {
        claims = default;

        if (!TryGetString(root, "iss", out var iss) ||
            !TryGetString(root, "kid", out var kid) ||
            !TryGetString(root, "sub", out var sub) ||
            !TryGetString(root, "resource", out var resource) ||
            !TryGetString(root, "tier", out var tier) ||
            !TryGetString(root, "nonce", out var nonce) ||
            !TryGetIntegerNumericDate(root, "iat", out var iat) ||
            !TryGetIntegerNumericDate(root, "exp", out var exp))
        {
            return false;
        }

        if (!IsAbsoluteHttpsIssuer(iss) ||
            !KidPattern.IsMatch(kid) ||
            !LowerUuidPattern.IsMatch(sub) ||
            sub == "00000000-0000-0000-0000-000000000000" ||
            !TierPattern.IsMatch(tier) ||
            !NoncePattern.IsMatch(nonce) ||
            string.IsNullOrEmpty(resource))
        {
            return false;
        }

        claims = new RawClaims(iss, kid, sub, resource, tier, iat, exp, nonce);
        return true;
    }

    private static bool TryGetString(JsonElement root, string name, out string value)
    {
        value = "";
        if (!root.TryGetProperty(name, out var el) || el.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        var s = el.GetString();
        if (s is null)
        {
            return false;
        }

        value = s;
        return true;
    }

    private static bool TryGetIntegerNumericDate(JsonElement root, string name, out long value)
    {
        value = 0;
        if (!root.TryGetProperty(name, out var el) || el.ValueKind != JsonValueKind.Number)
        {
            return false;
        }

        var raw = el.GetRawText();
        if (raw.Contains('.') || raw.Contains('e', StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return el.TryGetInt64(out value);
    }

    private static bool IsAbsoluteHttpsIssuer(string iss)
    {
        if (!Uri.TryCreate(iss, UriKind.Absolute, out var uri))
        {
            return false;
        }

        if (uri.Scheme != Uri.UriSchemeHttps &&
            !(uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback))
        {
            return false;
        }

        if (!string.IsNullOrEmpty(uri.Query) ||
            !string.IsNullOrEmpty(uri.Fragment) ||
            !string.IsNullOrEmpty(uri.UserInfo))
        {
            return false;
        }

        // No path beyond empty or "/"
        var path = uri.AbsolutePath.TrimEnd('/');
        if (path.Length > 0)
        {
            return false;
        }

        // No trailing slash on the configured form
        if (iss.EndsWith('/'))
        {
            return false;
        }

        return true;
    }

    private readonly record struct RawClaims(
        string Issuer,
        string KeyId,
        string Subject,
        string Resource,
        string Tier,
        long IssuedAtUnix,
        long ExpiresAtUnix,
        string Nonce);
}
