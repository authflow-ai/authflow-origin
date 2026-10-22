using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;
using Rail.Kernel.OriginProtocol;
using Rail.OriginProxy.Verification;
using Yarp.ReverseProxy.Forwarder;

namespace Rail.OriginProxy.Forwarding;

/// <summary>
/// Verifies the Origin Protocol identity header, then streaming-forwards via YARP with
/// <c>X-Authflow-User</c> / <c>X-Authflow-Tier</c> / <c>X-Authflow-Nonce</c> set from claims.
/// </summary>
public sealed class OriginProxyHandler
{
    private static readonly ForwarderRequestConfig RequestConfig = new()
    {
        ActivityTimeout = TimeSpan.FromMinutes(15)
    };

    private readonly OriginIdentityVerifier _verifier;
    private readonly IHttpForwarder _forwarder;
    private readonly HttpMessageInvoker _invoker;
    private readonly string _destinationPrefix;

    public OriginProxyHandler(
        OriginIdentityVerifier verifier,
        IHttpForwarder forwarder,
        HttpMessageInvoker upstreamInvoker,
        AuthflowOptions options)
    {
        _verifier = verifier;
        _forwarder = forwarder;
        _invoker = upstreamInvoker;
        _destinationPrefix = options.UpstreamBaseUri.TrimEnd('/');
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var (identity, error) = await _verifier.VerifyAsync(context.Request.Headers, context.RequestAborted);
        if (error is not null || identity is null)
        {
            await WriteRejectAsync(context, error ?? OriginErrorCode.MalformedIdentity);
            return;
        }

        var transformer = new VerifiedRequestTransformer(identity);
        var forwardError = await _forwarder.SendAsync(
            context,
            _destinationPrefix,
            _invoker,
            RequestConfig,
            transformer,
            context.RequestAborted);

        if (forwardError is not ForwarderError.None && !context.Response.HasStarted)
        {
            context.Response.StatusCode = StatusCodes.Status502BadGateway;
        }
    }

    public static async Task WriteRejectAsync(HttpContext context, OriginErrorCode code)
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        context.Response.ContentType = "application/json; charset=utf-8";
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers[OriginProxyHeaders.Verifier] = OriginProxyHeaders.VerifierVersion;
        context.Response.Headers.Remove("WWW-Authenticate");

        var body = new RejectBody
        {
            Error = OriginProtocolErrors.InvalidOriginIdentity,
            ErrorCode = code.ToWire(),
            ErrorDescription = code.Description()
        };

        await context.Response.WriteAsJsonAsync(body, context.RequestAborted);
    }

    private sealed class RejectBody
    {
        [JsonPropertyName("error")]
        public required string Error { get; init; }

        [JsonPropertyName("error_code")]
        public required string ErrorCode { get; init; }

        [JsonPropertyName("error_description")]
        public required string ErrorDescription { get; init; }
    }

    private sealed class VerifiedRequestTransformer : HttpTransformer
    {
        private readonly VerifiedOriginIdentity _identity;

        public VerifiedRequestTransformer(VerifiedOriginIdentity identity)
        {
            _identity = identity;
        }

        public override async ValueTask TransformRequestAsync(
            HttpContext httpContext,
            HttpRequestMessage proxyRequest,
            string destinationPrefix,
            CancellationToken cancellationToken)
        {
            await base.TransformRequestAsync(httpContext, proxyRequest, destinationPrefix, cancellationToken);

            proxyRequest.Headers.Host = null;

            proxyRequest.Headers.Remove(OriginProtocolConstants.IdentityHeaderName);
            proxyRequest.Headers.Remove(OriginProxyHeaders.User);
            proxyRequest.Headers.Remove(OriginProxyHeaders.Tier);
            proxyRequest.Headers.Remove(OriginProxyHeaders.Nonce);

            proxyRequest.Headers.TryAddWithoutValidation(OriginProxyHeaders.User, _identity.Subject);
            proxyRequest.Headers.TryAddWithoutValidation(OriginProxyHeaders.Tier, _identity.Tier);
            proxyRequest.Headers.TryAddWithoutValidation(OriginProxyHeaders.Nonce, _identity.Nonce);

            proxyRequest.RequestUri = RequestUtilities.MakeDestinationAddress(
                destinationPrefix,
                httpContext.Request.Path,
                httpContext.Request.QueryString);
        }
    }
}
