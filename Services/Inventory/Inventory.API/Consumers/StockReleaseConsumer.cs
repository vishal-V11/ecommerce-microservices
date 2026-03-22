using Inventory.API.DTO;
using Inventory.API.Interfaces;
using Inventory.API.Messaging;
using Shared.Messaging.Constants;
using Shared.Messaging.Events.Stock;
using System.Text.Json;

namespace Inventory.API.Consumers
{
    /// <summary>
    /// A background service that handles the Sage Realse Stock after payment failure.
    /// </summary>
    public class StockReleaseConsumer : BackgroundService
    {
        private readonly ILogger<StockReleaseConsumer> _logger;
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly KafkaFactory _kafkaFactory;
        public StockReleaseConsumer(ILogger<StockReleaseConsumer> logger,
            IServiceScopeFactory scopeFactory,
            KafkaFactory kafkaFactory
            )
        {
            _logger = logger;
            _scopeFactory = scopeFactory;
            _kafkaFactory = kafkaFactory;
        }

        protected async override Task ExecuteAsync(CancellationToken stoppingToken)
        {
            using var consumer = _kafkaFactory.CreateConsumer(KafkaGroups.InventoryService);

            consumer.Subscribe(KafkaTopics.StockRelease);
            _logger.LogInformation("StockReleaseConsumer started.");


            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var result = consumer.Consume(stoppingToken);
                    var @event = JsonSerializer.Deserialize<StockReleaseEvent>(result.Message.Value);

                    if (@event is null)
                    {
                        _logger.LogWarning("Received null StockReleaseEvent. Skipping.");
                        consumer.Commit(result);
                        continue;
                    }

                    using (_logger.BeginScope(new Dictionary<string, object>
                    {
                        ["CorrelationId"] = @event.CorrelationId
                    }))
                    {
                        _logger.LogInformation("Stock release received for {ItemCount} items.", @event.Items.Count);

                        using var scope = _scopeFactory.CreateAsyncScope();
                        var inventoryService = scope.ServiceProvider.GetRequiredService<IInventoryService>();
                        var processedEventsRepository = scope.ServiceProvider.GetRequiredService<IProcessedEventsRepository>();

                        var alreadyProcessed = await processedEventsRepository.ExistsAsync(
                            @event.CorrelationId,
                            KafkaTopics.StockRelease,
                            stoppingToken);

                        if (alreadyProcessed)
                        {
                            _logger.LogWarning("Stock release already processed. Skipping duplicate.");
                            consumer.Commit(result);
                            continue;
                        }

                        var stockItems = @event.Items
                        .Select(i => new StockItemDto(i.ProductId, i.Quantity))
                        .ToList();

                        await inventoryService.ReleaseStockBatchAsync(stockItems, stoppingToken);

                        await processedEventsRepository.AddAsync(
                            @event.CorrelationId,
                            KafkaTopics.StockRelease,
                            stoppingToken);

                        consumer.Commit(result);

                        _logger.LogInformation("Stock released successfully for {ItemCount} items.", @event.Items.Count);
                    }
                }
                catch (OperationCanceledException)
                {

                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Unhandled error processing StockReleaseEvent.");
                }
            }

            consumer.Close();
        }
    }
}
