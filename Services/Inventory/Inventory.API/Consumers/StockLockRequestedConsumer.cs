using Confluent.Kafka;
using Inventory.API.DTO;
using Inventory.API.Exceptions;
using Inventory.API.Interfaces;
using Inventory.API.Persistence.Repositories;
using Inventory.API.Settings;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.Extensions.Options;
using Polly.Registry;
using Shared.Messaging.Constants;
using Shared.Messaging.Events.Stock;
using System.Text.Json;

namespace Inventory.API.Consumers
{
    /// <summary>
    /// A background service that handles the Sage stock locking for the order it follows atomicity all or none.
    /// </summary>
    public class StockLockRequestedConsumer : BackgroundService
    {
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly ILogger<StockLockRequestedConsumer> _logger;
        private readonly KafkaSettings _kafkaSettings;
        public StockLockRequestedConsumer(IServiceScopeFactory scopeFactory,
            ILogger<StockLockRequestedConsumer> logger,
            ResiliencePipelineProvider<string> pipelineProvider,
            IOptions<KafkaSettings> options
            )
        {
            _logger = logger;
            _scopeFactory = scopeFactory;
            _kafkaSettings = options.Value;
        }

        protected async override Task ExecuteAsync(CancellationToken stoppingToken)
        {
            var consumerConfig = new ConsumerConfig
            {
                BootstrapServers = _kafkaSettings.BootstrapServers,
                GroupId = KafkaGroups.InventoryService,
                AutoOffsetReset = AutoOffsetReset.Earliest,
                EnableAutoCommit = false
            };

            var producerConfig = new ProducerConfig
            {
                BootstrapServers = _kafkaSettings.BootstrapServers
            };

            using var consumer = new ConsumerBuilder<string, string>(consumerConfig).Build();
            using var producer = new ProducerBuilder<string, string>(producerConfig).Build();

            consumer.Subscribe(KafkaTopics.StockLockRequested);

            _logger.LogInformation("StockLockRequestedConsumer started.");

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var result = consumer.Consume(stoppingToken);
                    var @event = JsonSerializer.Deserialize<StockLockRequestedEvent>(result.Message.Value);

                    if (@event is null)
                    {
                        _logger.LogWarning("Received null StockLockRequestedEvent. Skipping.");
                        consumer.Commit(result);
                        continue;
                    }

                    using (_logger.BeginScope(new Dictionary<string, object>
                    {
                        ["CorrelationId"] = @event.CorrelationId,
                        ["UserId"] = @event.UserId
                    }))
                    {
                        _logger.LogInformation("Stock lock requested for {ItemCount} items.", @event.Items.Count);

                        using var scope = _scopeFactory.CreateAsyncScope();
                        var processedEventsRepository = scope.ServiceProvider
                                .GetRequiredService<IProcessedEventsRepository>();

                        var inventoryService = scope.ServiceProvider
                            .GetRequiredService<IInventoryService>();

                        var alreadyProcessed = await processedEventsRepository.ExistsAsync(@event.CorrelationId, KafkaTopics.StockLockRequested, stoppingToken);
                        if (alreadyProcessed)
                        {
                            _logger.LogWarning("Stock lock already processed. Skipping duplicate.");
                            consumer.Commit(result);
                            continue;
                        }


                        var stockItems = @event.Items
                            .Select(x => new StockItemDto(x.ProductId, x.Quantity))
                            .ToList();

                        try
                        {
                            await inventoryService.LockStockBatchAsync(stockItems, stoppingToken);

                            await processedEventsRepository.AddAsync(
                                @event.CorrelationId,
                                KafkaTopics.StockLockRequested,
                                stoppingToken);

                            var lockedEvent = new StockLockedEvent(
                                @event.CorrelationId,
                                DateTime.UtcNow);

                            await producer.ProduceAsync(
                                KafkaTopics.StockLocked,
                                new Message<string, string>
                                {
                                    Key = @event.CorrelationId.ToString(),
                                    Value = JsonSerializer.Serialize(lockedEvent)
                                },
                                stoppingToken);

                            _logger.LogInformation("Stock locked successfully. StockLockedEvent published.");
                        }
                        catch (InsufficientStockException ex)
                        {
                            _logger.LogWarning(ex.Message);

                            await PublishStockLockFailedAsync(producer, @event.CorrelationId, ex.Message, stoppingToken);
                        }
                        catch (InventoryItemNotFoundException ex)
                        {
                            _logger.LogWarning(ex.Message);

                            await PublishStockLockFailedAsync(producer, @event.CorrelationId, ex.Message, stoppingToken);
                        }
                        catch (DbUpdateConcurrencyException ex)
                        {
                            _logger.LogError(ex, "Concurrency conflict persisted after all Polly retries exhausted.");

                            await PublishStockLockFailedAsync(producer, @event.CorrelationId, "Stock lock failed due to concurrency conflict.", stoppingToken);
                        }

                        consumer.Commit(result);

                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Unhandled error processing StockLockRequestedEvent.");
                }
            }

            consumer.Close();

        }

        private async Task PublishStockLockFailedAsync(
            IProducer<string, string> producer,
            Guid correlationId,
            string reason,
            CancellationToken ct)
        {
            var failedEvent = new StockLockFailedEvent(
                correlationId,
                reason,
                DateTime.UtcNow);

            await producer.ProduceAsync(
                KafkaTopics.StockLockFailed,
                new Message<string, string>
                {
                    Key = correlationId.ToString(),
                    Value = JsonSerializer.Serialize(failedEvent)
                },
                ct);

            _logger.LogInformation("StockLockFailedEvent published. Reason: {Reason}", reason);
        }
    }
}
