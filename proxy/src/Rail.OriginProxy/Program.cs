using Microsoft.Extensions.Options;
using Rail.Kernel.Time;
using Rail.OriginProxy;
using Rail.OriginProxy.Forwarding;
using Rail.OriginProxy.Keys;
using Rail.OriginProxy.Nonce;
using Rail.OriginProxy.Verification;
using Yarp.ReverseProxy.Forwarder;

var builder = WebApplication.CreateBuilder(args);

// Issuer and Resource must be the receipt's canonical spellings (AuthflowOptionsValidator):
// anything else fails every request, so it fails startup instead.
builder.Services.AddOptions<AuthflowOptions>()
    .Bind(builder.Configuration.GetSection(AuthflowOptions.SectionName))
    .ValidateDataAnnotations()
    .Validate(
        o => Uri.TryCreate(o.UpstreamBaseUri, UriKind.Absolute, out _),
        "Authflow:UpstreamBaseUri must be an absolute URI.")
    .ValidateOnStart();
builder.Services.AddSingleton<IValidateOptions<AuthflowOptions>, AuthflowOptionsValidator>();

builder.Services.AddSingleton<IClock, SystemClock>();
builder.Services.AddNonceReplayCache(builder.Configuration);
builder.Services.AddSingleton<OriginKeyCache>();
builder.Services.AddSingleton<OriginIdentityVerifier>();
builder.Services.AddHttpForwarder();
builder.Services.AddSingleton(_ =>
{
    var handler = new SocketsHttpHandler
    {
        UseProxy = false,
        UseCookies = false,
        ConnectTimeout = TimeSpan.FromSeconds(10),
        EnableMultipleHttp2Connections = true,
        // Streaming MCP: do not impose an idle response timeout on the invoker.
        PooledConnectionIdleTimeout = Timeout.InfiniteTimeSpan
    };
    return new HttpMessageInvoker(handler, disposeHandler: true);
});

builder.Services.AddHttpClient(OriginKeyCache.HttpClientName)
    .ConfigureHttpClient(client =>
    {
        client.Timeout = TimeSpan.FromSeconds(10);
    });

builder.Services.AddSingleton(sp =>
{
    var options = sp.GetRequiredService<IOptions<AuthflowOptions>>().Value;
    return new OriginProxyHandler(
        sp.GetRequiredService<OriginIdentityVerifier>(),
        sp.GetRequiredService<IHttpForwarder>(),
        sp.GetRequiredService<HttpMessageInvoker>(),
        options);
});

var app = builder.Build();

// §5.3: fetch the key document at process start before accepting traffic.
await app.Services.GetRequiredService<OriginKeyCache>().WarmAsync(CancellationToken.None);

// Container platforms probe the proxy's own port. A probe carries no identity header, so routing
// it through verification would 403 every liveness check and restart-loop the revision. Answered
// here and never forwarded: it says nothing about the upstream.
app.MapGet("/healthz", () => Results.Ok());

// Catch-all: every inbound request is verified before any upstream dispatch.
app.MapFallback(async context =>
{
    var handler = context.RequestServices.GetRequiredService<OriginProxyHandler>();
    await handler.InvokeAsync(context);
});

await app.RunAsync();

public partial class Program;
