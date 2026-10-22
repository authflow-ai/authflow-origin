using System.Collections.Concurrent;

namespace Rail.OriginProxy.Nonce;

/// <summary>
/// Process-local replay cache. Correct on exactly one replica.
/// </summary>
/// <remarks>
/// Scaling this proxy out without a shared store is a real correctness hole, not a theoretical one:
/// a replayed identity header that lands on a replica which has not seen the nonce is accepted. Set
/// <c>Authflow:NonceCacheRedis</c> to get <see cref="RedisNonceReplayCache"/> instead; without it the
/// proxy refuses to start unless <c>Authflow:SingleReplica=true</c> declares exactly one replica.
/// </remarks>
public sealed class MemoryNonceReplayCache : INonceReplayCache
{
    private readonly ConcurrentDictionary<string, long> _seen = new(StringComparer.Ordinal);
    private long _lastSweepUnix;

    public ValueTask<NonceRecordResult> TryRecordAsync(
        string nonce,
        DateTimeOffset retainUntilUtc,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nonce);

        SweepIfNeeded(DateTimeOffset.UtcNow);

        var result = _seen.TryAdd(nonce, retainUntilUtc.ToUnixTimeSeconds())
            ? NonceRecordResult.Recorded
            : NonceRecordResult.Replay;
        return ValueTask.FromResult(result);
    }

    private void SweepIfNeeded(DateTimeOffset now)
    {
        var nowUnix = now.ToUnixTimeSeconds();
        var last = Interlocked.Read(ref _lastSweepUnix);
        if (nowUnix - last < 30)
        {
            return;
        }

        if (Interlocked.CompareExchange(ref _lastSweepUnix, nowUnix, last) != last)
        {
            return;
        }

        foreach (var pair in _seen)
        {
            if (pair.Value < nowUnix)
            {
                _seen.TryRemove(pair.Key, out _);
            }
        }
    }
}
