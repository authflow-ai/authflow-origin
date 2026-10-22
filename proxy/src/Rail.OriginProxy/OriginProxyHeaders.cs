namespace Rail.OriginProxy;

/// <summary>
/// Plain identity headers set on a verified forward. Client-supplied values are stripped so the
/// upstream only ever sees claims this process just verified.
/// </summary>
public static class OriginProxyHeaders
{
    public const string Verifier = "X-Authflow-Verifier";

    public static readonly string VerifierVersion =
        "proxy/" + typeof(OriginProxyHeaders).Assembly.GetName().Version!.ToString(3);

    public const string User = "X-Authflow-User";
    public const string Tier = "X-Authflow-Tier";
    public const string Nonce = "X-Authflow-Nonce";
}
