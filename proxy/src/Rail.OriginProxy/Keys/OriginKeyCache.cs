using System.Collections.Immutable;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Rail.Kernel.OriginProtocol;
using Rail.Kernel.Time;

namespace Rail.OriginProxy.Keys;

/// <summary>
/// §5 key discovery: fetch <c>{iss}/.well-known/authflow-origin-keys</c>, cache ≤3600s, one forced
/// refresh on unknown kid, keep-last-good, fail closed.
/// </summary>
/// <remarks>
/// Fetches are rationed because the trigger is attacker-controlled: anyone who can reach the proxy
/// can name a kid that does not exist. A caller that queued behind a fetch uses that fetch's result
/// instead of making its own, and refreshes forced by unknown kids are capped at
/// <see cref="MaxForcedRefreshesPerInterval"/> per <see cref="MinForcedRefreshInterval"/>, one per distinct
/// kid. Without both, a burst of junk headers became one
/// sequential fetch each, and anything else that needed the lock waited behind them. A request whose
/// kid is already cached never touches the lock.
/// </remarks>
public sealed class OriginKeyCache
{
    public const string HttpClientName = "authflow-origin-keys";

    public static readonly TimeSpan MaxCacheAge = TimeSpan.FromSeconds(3600);

    /// <summary>
    /// The window over which refreshes forced by unknown kids are counted, and the gap between retries
    /// of a failed refresh of an expired document (§5.3: "do not refresh in a tight loop"). Spaces out forced
    /// refreshes only, so a rotation just after a routine fetch is still found on its first header.
    /// </summary>
    public static readonly TimeSpan MinForcedRefreshInterval = TimeSpan.FromSeconds(30);

    /// <summary>
    /// How many refreshes unknown kids may force in one <see cref="MinForcedRefreshInterval"/>, each
    /// for a different kid. One was too few: the rail starts signing with a new key as soon as it
    /// publishes it (§5.4), so a single stray header that forced a fetch just before a rotation left
    /// the first headers signed with the new key rejected as unknown_key for up to 30 s.
    /// </summary>
    public const int MaxForcedRefreshesPerInterval = 3;

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly AuthflowOptions _options;
    private readonly IClock _clock;
    private readonly SemaphoreSlim _refreshLock = new(1, 1);

    private ImmutableDictionary<string, OriginVerificationKey> _keys =
        ImmutableDictionary<string, OriginVerificationKey>.Empty;
    private DateTimeOffset _fetchedAt = DateTimeOffset.MinValue;
    private bool _hasDocument;

    // Guarded by _refreshLock, except _attempts, which callers read before queuing for it.
    private long _attempts;
    private DateTimeOffset _lastAttemptAt = DateTimeOffset.MinValue;

    // Refreshes forced by unknown kids inside the current interval, oldest first. A kid appears at
    // most once, and the list never holds more than MaxForcedRefreshesPerInterval entries.
    private readonly Queue<(string Kid, DateTimeOffset At)> _forced = new();

    private enum RefreshReason
    {
        /// <summary>Startup warm, or no document has ever been fetched.</summary>
        Missing,

        /// <summary>The held document is past <see cref="MaxCacheAge"/>.</summary>
        Expired,

        /// <summary>A header named a kid the held document does not have.</summary>
        UnknownKid
    }

    public OriginKeyCache(
        IHttpClientFactory httpClientFactory,
        IOptions<AuthflowOptions> options,
        IClock clock)
    {
        _httpClientFactory = httpClientFactory;
        _options = options.Value;
        _clock = clock;
    }

    public async Task WarmAsync(CancellationToken cancellationToken)
    {
        await RefreshAsync(RefreshReason.Missing, cancellationToken);
    }

    public async Task<KeyLookupResult> ResolveAsync(string kid, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(kid);

        await EnsureFreshAsync(cancellationToken);

        if (!_hasDocument)
        {
            await RefreshAsync(RefreshReason.Missing, cancellationToken);
            if (!_hasDocument)
            {
                return KeyLookupResult.Unavailable;
            }
        }

        if (_keys.TryGetValue(kid, out var hit))
        {
            return KeyLookupResult.Found(hit);
        }

        // Unknown kid: force one refresh even if the cache is still fresh (§5.3).
        await RefreshAsync(RefreshReason.UnknownKid, cancellationToken, kid);

        if (_keys.TryGetValue(kid, out hit))
        {
            return KeyLookupResult.Found(hit);
        }

        return KeyLookupResult.Unknown;
    }

    private async Task EnsureFreshAsync(CancellationToken cancellationToken)
    {
        if (!_hasDocument)
        {
            return;
        }

        if (_clock.UtcNow - _fetchedAt <= MaxCacheAge)
        {
            return;
        }

        await RefreshAsync(RefreshReason.Expired, cancellationToken);
    }

    private async Task RefreshAsync(RefreshReason reason, CancellationToken cancellationToken, string? kid = null)
    {
        var attemptsBeforeQueuing = Interlocked.Read(ref _attempts);

        await _refreshLock.WaitAsync(cancellationToken);
        try
        {
            // Someone else fetched while this caller queued; their result is as fresh as ours would be.
            if (Interlocked.Read(ref _attempts) != attemptsBeforeQueuing)
            {
                return;
            }

            var now = _clock.UtcNow;
            if (reason == RefreshReason.UnknownKid)
            {
                while (_forced.Count > 0 && now - _forced.Peek().At >= MinForcedRefreshInterval)
                {
                    _forced.Dequeue();
                }

                // A kid that already caused a refresh in this interval is answered by that fetch, and
                // a burst of different junk kids is capped, so neither can be used to hammer the rail.
                if (_forced.Count >= MaxForcedRefreshesPerInterval || _forced.Any(entry => entry.Kid == kid))
                {
                    return;
                }
            }
            else if (reason == RefreshReason.Expired && now - _lastAttemptAt < MinForcedRefreshInterval)
            {
                return;
            }

            // A fetch the caller abandoned says nothing about the key document: it neither counts as an
            // attempt (queued callers must still make their own) nor spends the interval's allowance.
            var abandoned = false;
            try
            {
                await FetchAsync(cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                abandoned = true;
                throw;
            }
            finally
            {
                if (!abandoned)
                {
                    _lastAttemptAt = now;
                    if (reason == RefreshReason.UnknownKid)
                    {
                        _forced.Enqueue((kid!, now));
                    }

                    Interlocked.Increment(ref _attempts);
                }
            }
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    private async Task FetchAsync(CancellationToken cancellationToken)
    {
        try
        {
            var client = _httpClientFactory.CreateClient(HttpClientName);
            var url = _options.Issuer.TrimEnd('/') + OriginProtocolConstants.VerificationKeysPath;

            using var response = await client.GetAsync(url, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return;
            }

            OriginKeysDocumentDto? document;
            try
            {
                document = await response.Content.ReadFromJsonAsync<OriginKeysDocumentDto>(
                    cancellationToken: cancellationToken);
            }
            catch (JsonException)
            {
                return;
            }
            catch (NotSupportedException)
            {
                return;
            }

            if (!TryParseDocument(document, _options.Issuer, out var parsed))
            {
                return;
            }

            _keys = parsed;
            _fetchedAt = _clock.UtcNow;
            _hasDocument = true;
        }
        catch (HttpRequestException)
        {
            // Keep the last good document; the caller fails closed only if there never was one.
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
        }
    }

    internal static bool TryParseDocument(
        OriginKeysDocumentDto? document,
        string configuredIssuer,
        out ImmutableDictionary<string, OriginVerificationKey> keys)
    {
        keys = ImmutableDictionary<string, OriginVerificationKey>.Empty;

        if (document is null)
        {
            return false;
        }

        if (!string.Equals(document.Issuer, configuredIssuer, StringComparison.Ordinal))
        {
            return false;
        }

        if (!string.Equals(document.ProtocolVersion, OriginProtocolConstants.Version1, StringComparison.Ordinal))
        {
            return false;
        }

        if (document.Keys is null || document.Keys.Length == 0)
        {
            return false;
        }

        var builder = ImmutableDictionary.CreateBuilder<string, OriginVerificationKey>(StringComparer.Ordinal);
        foreach (var jwk in document.Keys)
        {
            if (!string.IsNullOrEmpty(jwk.D))
            {
                return false;
            }

            if (!IsV1PublicJwk(jwk))
            {
                // Ignore non-v1 shapes so a future key type can coexist.
                continue;
            }

            if (!Base64Url.TryDecode(jwk.X!, out var raw) || raw.Length != 32)
            {
                continue;
            }

            if (builder.ContainsKey(jwk.KeyId!))
            {
                return false;
            }

            builder.Add(jwk.KeyId!, new OriginVerificationKey
            {
                KeyId = jwk.KeyId!,
                PublicKeyRaw = raw
            });
        }

        if (builder.Count == 0)
        {
            return false;
        }

        keys = builder.ToImmutable();
        return true;
    }

    private static bool IsV1PublicJwk(OriginPublicJwkDto jwk) =>
        string.Equals(jwk.KeyType, "OKP", StringComparison.Ordinal) &&
        string.Equals(jwk.Curve, "Ed25519", StringComparison.Ordinal) &&
        string.Equals(jwk.Use, "sig", StringComparison.Ordinal) &&
        string.Equals(jwk.Algorithm, "EdDSA", StringComparison.Ordinal) &&
        !string.IsNullOrEmpty(jwk.KeyId) &&
        !string.IsNullOrEmpty(jwk.X);
}

public readonly struct KeyLookupResult
{
    private KeyLookupResult(KeyLookupStatus status, OriginVerificationKey? key)
    {
        Status = status;
        Key = key;
    }

    public KeyLookupStatus Status { get; }

    public OriginVerificationKey? Key { get; }

    public static KeyLookupResult Found(OriginVerificationKey key) => new(KeyLookupStatus.Found, key);

    public static KeyLookupResult Unknown => new(KeyLookupStatus.Unknown, null);

    public static KeyLookupResult Unavailable => new(KeyLookupStatus.Unavailable, null);
}

public enum KeyLookupStatus
{
    Found,
    Unknown,
    Unavailable
}
