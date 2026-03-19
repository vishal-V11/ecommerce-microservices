using Confluent.Kafka;
using Inventory.API.DTO;
using Inventory.API.Interfaces;
using Inventory.API.Persistence.Repositories;
using Inventory.API.Settings;
using Microsoft.Extensions.Options;
using Shared.Messaging.Constants;
using Shared.Messaging.Events.Stock;
using System.Text.Json;

namespace Inventory.API.Consumers
{
    /// <summary>
    /// A background service that handles the Sage Confirm Stock .
    /// Adjust the 
    /// </summary>
    public class StockConfirmConsumer : BackgroundService
    {
        private readonly ILogger<StockConfirmConsumer> _logger;
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly KafkaSettings _kafkaSettings;

        public StockConfirmConsumer(ILogger<StockConfirmConsumer> logger,
            IServiceScopeFactory scopeFactory,
            IOptions<KafkaSettings> options
            )
        {
            _logger = logger;
            _scopeFactory = scopeFactory;
            _kafkaSettings = options.Value;
        }


        protected async override Task ExecuteAsync(CancellationToken stoppingToken)
        {
            var consumerConfig = new ConsumerConfig()
            {
                BootstrapServers = _kafkaSettings.BootstrapServers,
                GroupId = KafkaGroups.InventoryService,
                AutoOffsetReset = AutoOffsetReset.Earliest,
                EnableAutoCommit = false
            };

            var producerConfig = new ProducerConfig()
            {
                BootstrapServers = _kafkaSettings.BootstrapServers
            };

            using var consumer = new ConsumerBuilder<string, string>(consumerConfig).Build();

            consumer.Subscribe(KafkaTopics.StockConfirm);

            _logger.LogInformation("StockConfirmConsumer started.");

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var result = consumer.Consume(stoppingToken);

                    var @event = JsonSerializer.Deserialize<StockConfirmEvent>(result.Message.Value);

                    if (@event is null)
                    {
                        _logger.LogWarning("Received null StockConfirmEvent. Skipping.");
                        consumer.Commit(result);
                        continue;
                    }

                    using (_logger.BeginScope(new Dictionary<string, object>
                    {
                        ["CorrelationId"] = @event.CorrelationId
                    }))
                    {
                        _logger.LogInformation("Stock confirm received for {ItemCount} items.", @event.Items.Count);

                        using var scope = _scopeFactory.CreateAsyncScope();
                        var inventoryService = scope.ServiceProvider
                            .GetRequiredService<IInventoryService>();

                        var processedEventRepository = scope.ServiceProvider
                            .GetRequiredService<IProcessedEventsRepository>();

                        var alreadyProcessed = await processedEventRepository.ExistsAsync(@event.CorrelationId, KafkaTopics.StockConfirm, stoppingToken);
                        if (alreadyProcessed)
                        {
                            _logger.LogWarning("Stock confirm already processed. Skipping duplicate.");
                            consumer.Commit(result);
                            continue;
                        }

                        List<StockItemDto> items = @event.Items
                            .Select(x => new StockItemDto(x.ProductId, x.Quantity))
                            .ToList();

                        await inventoryService.ConfirmStockBatchAsync(items,stoppingToken);

                        await processedEventRepository.AddAsync(@event.CorrelationId,
                            KafkaTopics.StockConfirm,
                            stoppingToken);

                        consumer.Commit(result);

                        _logger.LogInformation("Stock confirmed successfully for {ItemCount} items.", @event.Items.Count);
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Unhandled error processing StockConfirmEvent.");
                }
            }

            consumer.Close();
        }
    }
}
