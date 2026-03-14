using Cart.Application.Abstractions;
using Cart.Infrastructure.Common;
using StackExchange.Redis;
using System.Text.Json;

namespace Cart.Infrastructure.Repositories
{
    public sealed class CartRepository(IConnectionMultiplexer redis):ICartRepository
    {
        private readonly IDatabase _db = redis.GetDatabase();
        private static readonly TimeSpan CartExpiry = TimeSpan.FromDays(7);
        private const string CartKeyPrefix = "cart:";

        // TODO: Migrate to Redis Hash (HSET/HGET) for large carts to avoid full serialization on single item updates

        private static string CartKey(string userId) => $"{CartKeyPrefix}{userId}";

        public async Task<Domain.Entities.Cart?> GetCartAsync(string userId,CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            var data = await _db.StringGetAsync(CartKey(userId));

            if(data.IsNullOrEmpty) return null;

            return JsonSerializer.Deserialize<Domain.Entities.Cart>(data!, JsonSerializerConfig.Default);
        }

        public async Task SaveCartAsync(Domain.Entities.Cart cart,CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            var data = JsonSerializer.Serialize(cart, JsonSerializerConfig.Default);
            await _db.StringSetAsync(CartKey(cart.UserId), data, CartExpiry);
        }

        public async Task DeleteCartAsync(string userId, CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            await _db.KeyDeleteAsync(CartKey(userId));
        }

    }
}
