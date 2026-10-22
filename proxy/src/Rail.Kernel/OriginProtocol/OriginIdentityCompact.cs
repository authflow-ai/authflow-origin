using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Rail.Kernel.Primitives;

namespace Rail.Kernel.OriginProtocol;

/// <summary>
/// Compact form <c>v1;&lt;claims&gt;;&lt;signature&gt;</c>. Signing input is the ASCII bytes of
/// <c>v1;</c> concatenated with the on-wire claims token — not the JSON, not a JWT.
/// </summary>
public static class OriginIdentityCompact
{
    public static string EncodeClaims(OriginIdentityClaims claims)
    {
        ArgumentNullException.ThrowIfNull(claims);

        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            Indented = false
        }))
        {
            writer.WriteStartObject();
            writer.WriteString("iss", claims.Issuer);
            writer.WriteString("kid", claims.KeyId);
            writer.WriteString("sub", claims.Subject.ToString());
            writer.WriteString("resource", claims.Resource.Canonical);
            writer.WriteString("tier", claims.Tier);
            writer.WriteNumber("iat", claims.IssuedAtUnix);
            writer.WriteNumber("exp", claims.ExpiresAtUnix);
            writer.WriteString("nonce", claims.Nonce);
            writer.WriteEndObject();
        }

        return Base64Url.Encode(buffer.ToArray());
    }

    public static byte[] SigningInput(string claimsBase64Url)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(claimsBase64Url);
        return Encoding.ASCII.GetBytes(OriginProtocolConstants.Version1 + ";" + claimsBase64Url);
    }

    public static string HeaderValue(string claimsBase64Url, string signatureBase64Url)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(claimsBase64Url);
        ArgumentException.ThrowIfNullOrWhiteSpace(signatureBase64Url);
        return OriginProtocolConstants.Version1 + ";" + claimsBase64Url + ";" + signatureBase64Url;
    }

    public static bool TryParseClaims(string claimsBase64Url, out OriginIdentityClaims claims)
    {
        claims = null!;
        if (!Base64Url.TryDecode(claimsBase64Url, out var json))
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            if (!root.TryGetProperty("iss", out var iss) || iss.ValueKind != JsonValueKind.String ||
                !root.TryGetProperty("kid", out var kid) || kid.ValueKind != JsonValueKind.String ||
                !root.TryGetProperty("sub", out var sub) || sub.ValueKind != JsonValueKind.String ||
                !root.TryGetProperty("resource", out var resource) || resource.ValueKind != JsonValueKind.String ||
                !root.TryGetProperty("tier", out var tier) || tier.ValueKind != JsonValueKind.String ||
                !root.TryGetProperty("iat", out var iat) || iat.ValueKind != JsonValueKind.Number ||
                !root.TryGetProperty("exp", out var exp) || exp.ValueKind != JsonValueKind.Number ||
                !root.TryGetProperty("nonce", out var nonce) || nonce.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            if (!UserId.TryParse(sub.GetString(), out var user) ||
                !ResourceUri.TryCreate(resource.GetString(), out var uri) ||
                !iat.TryGetInt64(out var issued) ||
                !exp.TryGetInt64(out var expires))
            {
                return false;
            }

            claims = new OriginIdentityClaims
            {
                Issuer = iss.GetString()!,
                KeyId = kid.GetString()!,
                Subject = user,
                Resource = uri,
                Tier = tier.GetString()!,
                IssuedAtUnix = issued,
                ExpiresAtUnix = expires,
                Nonce = nonce.GetString()!
            };
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
