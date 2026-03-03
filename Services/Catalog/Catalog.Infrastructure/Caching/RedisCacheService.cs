using Catalog.Application.Abstractions;
using DnsClient.Internal;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;
using System.Text.Json;

namespace Catalog.Infrastructure.Services
{
    public class RedisCacheService : ICacheService
    {

        private readonly IConnectionMultiplexer _redis;
        private readonly IDatabase _db;
        private readonly ILogger<RedisCacheService> _logger;

        public RedisCacheService(IConnectionMultiplexer redis,ILogger<RedisCacheService> logger)
        {
            _redis = redis;
            _db = _redis.GetDatabase();
            _logger = logger;
        }

        public async Task<T?> GetAsync<T>(string key, CancellationToken cancellationToken = default) where T : class
        {

            var value = await _db.StringGetAsync(key);
            if (!value.HasValue) return null;

            return JsonSerializer.Deserialize<T>(value!);
        }
        public async Task SetAsync<T>(string key, T value, TimeSpan? expiration = null, CancellationToken cancellationToken = default) where T : class
        {
            var json = JsonSerializer.Serialize(value);
            await _db.StringSetAsync(key, json, expiration, When.NotExists);
        }
        public async Task RemoveAsync(string key, CancellationToken cancellationToken = default)
        {
            await _db.KeyDeleteAsync(key);
        }

        public async Task<T> GetOrCreateAsync<T>(string key, Func<Task<T>> factory, TimeSpan? expiration = null, CancellationToken cancellationToken = default) where T : class
        {
            var existing = await GetAsync<T>(key, cancellationToken);
            if (existing is not null)
                return existing;

            var value = await factory();
            await SetAsync(key, value, expiration, cancellationToken);
            return value;
        }


        public async Task RemoveByPrefixAsync(string prefix, CancellationToken cancellationToken = default)
        {
            var server = _redis.GetServer(_redis.GetEndPoints().First());
            var keys = server.Keys(pattern: $"{prefix}*").ToArray();
            foreach (var key in keys)
                await _db.KeyDeleteAsync(key);
        }
        public async Task<bool> ExistsAsync(string key, CancellationToken cancellationToken = default)
        {
            return await _db.KeyExistsAsync(key);
        }

    }
}
