using Microsoft.Extensions.Logging;
using StackExchange.Redis;

namespace Rail.OriginProxy.Nonce;

/// <summary>
/// Shared replay cache, so the sidecar can front a horizontally-scaled origin.
/// </summary>
/// <remarks>
/// Claiming a nonce has to be atomic, which is why this uses Redis <c>SET key value NX PX</c>
/// directly rather than <c>IDistributedCache</c>: the latter has no set-if-absent, so a
/// read-then-write would leave a window in which two replicas both accept the same header — exactly
/// the bug a shared cache is here to close.
/// <para>
/// Keys expire on their own at the header's retention horizon, so there is no sweep to run and no
/// unbounded growth.
/// </para>
/// </remarks>
public sealed class RedisNonceReplayCache : INonceReplayCache
{
    /// <summary>Namespace prefix, so the cache can share a Redis instance with other workloads.</summary>
    public const string KeyPrefix = "authflow:origin:nonce:";

    private readonly IConnectionMultiplexer _redis;
    private readonly ILogger<RedisNonceReplayCache> _logger;

    public RedisNonceReplayCache(IConnectionMultiplexer redis, ILogger<RedisNonceReplayCache> logger)
    {
        _redis = redis;
        _logger = logger;
    }

    public async ValueTask<NonceRecordResult> TryRecordAsync(
        string nonce,
        DateTimeOffset retainUntilUtc,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nonce);

        var ttl = retainUntilUtc - DateTimeOffset.UtcNow;
        if (ttl <= TimeSpan.Zero)
        {
            // Already past its retention horizon: the expiry check rejects this header anyway, and
            // Redis refuses a non-positive TTL.
            return NonceRecordResult.Recorded;
        }

        try
        {
            var claimed = await _redis.GetDatabase().StringSetAsync(
                KeyPrefix + nonce,
                "1",
                ttl,
                When.NotExists);

            return claimed ? NonceRecordResult.Recorded : NonceRecordResult.Replay;
        }
        catch (RedisException ex)
        {
            _logger.LogError(ex, "Nonce replay cache is unavailable; failing closed.");
            return NonceRecordResult.Unavailable;
        }
        catch (TimeoutException ex)
        {
            _logger.LogError(ex, "Nonce replay cache timed out; failing closed.");
            return NonceRecordResult.Unavailable;
        }
    }
}
