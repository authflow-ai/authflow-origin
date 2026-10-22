namespace Rail.OriginProxy.Nonce;

/// <summary>Outcome of trying to claim a nonce for the first time.</summary>
public enum NonceRecordResult
{
    /// <summary>First sighting. The request may proceed.</summary>
    Recorded = 1,

    /// <summary>Already seen inside the retention window. Reject as a replay.</summary>
    Replay = 2,

    /// <summary>
    /// The store could not answer. Callers MUST fail closed: Origin Protocol §5/§6 treat a missing
    /// shared cache as an operational problem to fix, never as a reason to skip the replay check.
    /// </summary>
    Unavailable = 3,
}

/// <summary>
/// Records identity-header nonces so a replayed header is rejected.
/// </summary>
/// <remarks>
/// Asynchronous because the correct implementation for a horizontally-scaled origin is a shared
/// store, and a shared store is a network call. The in-process implementation is only correct on a
/// single replica: with more than one, a replayed header can land on a replica that has not seen it,
/// which is why the proxy starts on it only when <c>Authflow:SingleReplica</c> declares one replica.
/// </remarks>
public interface INonceReplayCache
{
    ValueTask<NonceRecordResult> TryRecordAsync(
        string nonce,
        DateTimeOffset retainUntilUtc,
        CancellationToken cancellationToken = default);
}
