using Cart.Application.Abstractions;
using Cart.Infrastructure.Mesagging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Shared.Messaging.Constants;
using Shared.Messaging.Events.Cart;
using StackExchange.Redis;
using System.Text.Json;

namespace Cart.Infrastructure.Consumer
{
    public class CartClearConsumer : BackgroundService
    {
        private readonly ILogger<CartClearConsumer> _logger;
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly IConnectionMultiplexer _redis;
        private readonly KafkaFactory _kafkaFactory;


        private const string IdempotencyKeyPrefix = "processed:";
        private static readonly TimeSpan IdempotencyTtl = TimeSpan.FromDays(7);

        public CartClearConsumer(ILogger<CartClearConsumer> logger,
            IServiceScopeFactory scopeFactory,
            IConnectionMultiplexer redis,
            KafkaFactory kafkaFactory)
        {
            _logger = logger;
            _scopeFactory = scopeFactory;
            _redis = redis;
            _kafkaFactory = kafkaFactory;
        }

        protected async override Task ExecuteAsync(CancellationToken stoppingToken)
        {
            using var consumer = _kafkaFactory.CreateConsumer(KafkaGroups.CartService);

            consumer.Subscribe(KafkaTopics.CartClear);

            _logger.LogInformation("CartClearConsumer started.");

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var result = consumer.Consume(stoppingToken);
                    var @event = JsonSerializer.Deserialize<CartClearEvent>(result.Message.Value);

                    if (@event is null)
                    {
                        _logger.LogWarning("Received null CartClearEvent. Skipping.");
                        consumer.Commit(result);
                        continue;
                    }

                    using (_logger.BeginScope(new Dictionary<string, object>
                    {
                        ["CorrelationId"] = @event.CorrelationId,
                        ["UserId"] = @event.UserId
                    }))
                    {
                        _logger.LogInformation("Cart clear event received.");

                        var db = _redis.GetDatabase();
                        var idempotencyKey = $"{IdempotencyKeyPrefix}{KafkaTopics.CartClear}:{@event.CorrelationId}";

                        var alreadyProcessed = await db.KeyExistsAsync(idempotencyKey);
                        if (alreadyProcessed)
                        {
                            _logger.LogWarning("Cart clear already processed. Skipping duplicate.");
                            consumer.Commit(result);
                            continue;
                        }

                        await using var scope = _scopeFactory.CreateAsyncScope();
                        var cartRepository = scope.ServiceProvider.GetRequiredService<ICartRepository>();

                        await cartRepository.DeleteCartAsync(@event.UserId, stoppingToken);

                        await db.StringSetAsync(idempotencyKey, "1", IdempotencyTtl);

                        consumer.Commit(result);

                        _logger.LogInformation("Cart cleared successfully.");
                    }
                }
                catch (OperationCanceledException)
                {

                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Unhandled error processing CartClearEvent.");
                }
            }

            consumer.Close();

        }
    }
}
