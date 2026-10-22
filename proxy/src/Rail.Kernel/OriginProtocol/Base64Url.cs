namespace Rail.Kernel.OriginProtocol;

/// <summary>RFC 4648 §5 base64url without padding. Canonical re-encode is required of verifiers.</summary>
public static class Base64Url
{
    public static string Encode(ReadOnlySpan<byte> data)
    {
        return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static bool TryDecode(string token, out byte[] bytes)
    {
        bytes = [];
        if (string.IsNullOrEmpty(token))
        {
            return false;
        }

        foreach (var c in token)
        {
            if (c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_')
            {
                continue;
            }

            return false;
        }

        var padded = token.Replace('-', '+').Replace('_', '/');
        padded = (padded.Length % 4) switch
        {
            0 => padded,
            2 => padded + "==",
            3 => padded + "=",
            _ => ""
        };
        if (padded.Length == 0)
        {
            return false;
        }

        try
        {
            bytes = Convert.FromBase64String(padded);
        }
        catch (FormatException)
        {
            return false;
        }

        return Encode(bytes) == token;
    }
}
