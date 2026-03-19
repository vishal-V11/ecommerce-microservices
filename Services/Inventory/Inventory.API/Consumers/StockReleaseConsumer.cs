using Confluent.Kafka;
using Inventory.API.DTO;
using Inventory.API.Interfaces;
using Inventory.API.Settings;
using Microsoft.Extensions.Options;
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
        private readonly KafkaSettings _KafkaSettings;
        public StockReleaseConsumer(ILogger<StockReleaseConsumer> logger,
            IServiceScopeFactory scopeFactory,
            IOptions<KafkaSettings> options
            )
        {
            _logger = logger;
            _scopeFactory = scopeFactory;
            _KafkaSettings = options.Value;
        }

        protected async override Task ExecuteAsync(CancellationToken stoppingToken)
        {
            var consumerConfig = new ConsumerConfig()
            {
                BootstrapServers = _KafkaSettings.BootstrapServers,
                GroupId = KafkaGroups.InventoryService,
                AutoOffsetReset = AutoOffsetReset.Earliest,
                EnableAutoCommit = false
            };

            using var consumer = new ConsumerBuilder<string, string>(consumerConfig).Build();

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
