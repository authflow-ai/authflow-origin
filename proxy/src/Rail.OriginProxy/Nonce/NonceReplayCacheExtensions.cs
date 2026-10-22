using StackExchange.Redis;

namespace Rail.OriginProxy.Nonce;

public static class NonceReplayCacheExtensions
{
    /// <summary>
    /// Registers the shared replay cache when <c>Authflow:NonceCacheRedis</c> is configured, and the
    /// process-local one otherwise. <see cref="AuthflowOptionsValidator"/> refuses to start on the
    /// process-local one unless <c>Authflow:SingleReplica</c> declares exactly one replica.
    /// </summary>
    /// <remarks>
    /// The connection is created eagerly so a bad connection string fails at startup rather than on
    /// the first request — at which point failing closed would reject live traffic.
    /// </remarks>
    public static IServiceCollection AddNonceReplayCache(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        var connectionString = configuration
            .GetSection(AuthflowOptions.SectionName)[nameof(AuthflowOptions.NonceCacheRedis)];

        if (string.IsNullOrWhiteSpace(connectionString))
        {
            services.AddSingleton<INonceReplayCache, MemoryNonceReplayCache>();
            return services;
        }

        services.AddSingleton<IConnectionMultiplexer>(
            _ => ConnectionMultiplexer.Connect(connectionString));
        services.AddSingleton<INonceReplayCache, RedisNonceReplayCache>();
        return services;
    }
}
