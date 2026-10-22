namespace Rail.Kernel.Primitives;

/// <summary>
/// The one canonical spelling shared by <see cref="ResourceUri"/> (a resource's identity) and
/// <see cref="ResourceAddress"/> (a URL a client connects to). Both types parse through here, so an
/// address that names the same URL as an identity has a byte-identical <c>Canonical</c> string, and
/// the registry can compare the two without either type converting into the other.
/// </summary>
/// <remarks>
/// A published format: changing these rules invalidates issued tokens and stored entitlements.
/// </remarks>
internal static class ResourceIdentifierForm
{
    public static bool TryParse(string? candidate, out Uri uri, out string canonical)
    {
        uri = null!;
        canonical = "";

        if (string.IsNullOrWhiteSpace(candidate) ||
            !Uri.TryCreate(candidate.Trim(), UriKind.Absolute, out var parsed))
        {
            return false;
        }

        // RFC 8707 forbids a fragment. We additionally forbid a query and userinfo so the canonical
        // form has exactly one spelling per resource.
        if (!string.IsNullOrEmpty(parsed.Fragment) ||
            !string.IsNullOrEmpty(parsed.Query) ||
            !string.IsNullOrEmpty(parsed.UserInfo))
        {
            return false;
        }

        if (!IsAllowedScheme(parsed))
        {
            return false;
        }

        uri = parsed;
        canonical = Canonicalise(parsed);
        return true;
    }

    /// <summary>
    /// HTTPS everywhere, with plaintext loopback allowed so the rail can be exercised end to end on
    /// a developer machine without a certificate.
    /// </summary>
    private static bool IsAllowedScheme(Uri uri) =>
        uri.Scheme == Uri.UriSchemeHttps ||
        (uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback);

    private static string Canonicalise(Uri uri)
    {
        var host = uri.Host.ToLowerInvariant();
        var authority = uri.IsDefaultPort ? host : $"{host}:{uri.Port}";

        // Trailing slashes are cosmetic in a URL but not in a dictionary key, so drop them. The
        // root path collapses to empty: "https://rails.authflow.ai/" and "https://rails.authflow.ai"
        // are the same resource.
        var path = uri.AbsolutePath.TrimEnd('/');

        return $"{uri.Scheme}://{authority}{path}";
    }

    /// <summary>
    /// Splits a canonical string into its authority (<c>scheme://host[:port]</c>) and path (empty, or
    /// starting with <c>/</c>). Works on the canonical string so scheme, host case, default port and
    /// trailing slash are decided in exactly one place.
    /// </summary>
    public static (string Authority, string Path) Split(string canonical)
    {
        var pathStart = canonical.IndexOf('/', canonical.IndexOf("://", StringComparison.Ordinal) + "://".Length);
        return pathStart < 0 ? (canonical, "") : (canonical[..pathStart], canonical[pathStart..]);
    }
}
