using Confluent.Kafka;
using Inventory.API.Entities;
using Inventory.API.Events;
using Inventory.API.Interfaces;
using Inventory.API.Settings;
using Messaging.Constants;
using Microsoft.Extensions.Options;
using System.Text.Json;

namespace Inventory.API.Consumers
{
    /// <summary>A Background Service Job to process kafka event when a new product is created </summary>
    public class ProductCreatedConsumer : BackgroundService
    {
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly KafkaSettings _kafkaSettings;
        private readonly ILogger<ProductCreatedConsumer> _logger;   
        public ProductCreatedConsumer(IServiceScopeFactory scopeFactory, IOptions<KafkaSettings> options,ILogger<ProductCreatedConsumer> logger)
        {
            _scopeFactory = scopeFactory;
            _kafkaSettings = options.Value;
            _logger = logger;
        }
        protected async override Task ExecuteAsync(CancellationToken ct)
        {
            var config = new ConsumerConfig
            {
                BootstrapServers = _kafkaSettings.BootstrapServers,

                // Identity of this consumer group
                // Kafka tracks offset independently per group
                // Multiple instances of this service share the same GroupId
                // Kafka distributes partitions across them automatically
                GroupId = KafkaGroups.InventoryService,

                // AutoOffsetReset only matters the very first time this GroupId connects
                // and no stored offset exists yet
                // Earliest = start reading from the very beginning of the topic
                // Latest = start reading only new messages from this point forward
                AutoOffsetReset = AutoOffsetReset.Earliest,

                // We manually commit offsets after successful processing
                // This ensures if the service crashes mid-processing
                // Kafka will replay the message on restart — nothing gets lost
                EnableAutoCommit = false
            };

            // Build the consumer
            // string = message key is our EventId (Guid as string)
            // string = message value is our JSON payload
            using var consumer = new ConsumerBuilder<string, string>(config).Build();

            consumer.Subscribe(KafkaTopics.ProductCreated);

            _logger.LogInformation(
                "ProductCreatedConsumer started. Listening on topic {Topic}."
                ,KafkaTopics.ProductCreated);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    // Blocking call — waits until a message arrives
                    // Unblocks and throws OperationCanceledException on app shutdown
                    var result = consumer.Consume(ct);

                    _logger.LogInformation("Received message on topic {Topic}. Offset: {Offset}"
                        ,KafkaTopics.ProductCreated
                        ,result.Offset);

                    var eventIdString = result.Message.Key;
                    if(!Guid.TryParse(eventIdString, out var eventId))
                    {
                        _logger.LogWarning("Invalid EventId key at offset {Offset}. Skipping.", result.Offset);
                        consumer.Commit(result);
                        continue;
                    }

                    // Deserialize payload
                    var @event = JsonSerializer.Deserialize<ProductCreatedEvent>(result.Message.Value);
                    if(@event is null)
                    {
                        _logger.LogWarning("Failed to Deserialize the ProductCreatedEvent at offset {Offset}. Skipping."
                            ,result.Offset);
                        consumer.Commit(result);
                        continue;
                    }

                    // BackgroundService is a singleton but repositories are scoped
                    // Create a fresh scope per message to resolve scoped services safely
                    using var scope = _scopeFactory.CreateScope();
                    var inventoryRepository = scope.ServiceProvider
                            .GetRequiredService<IInventoryRepository>();

                    var processedEventRepository = scope.ServiceProvider
                            .GetRequiredService<IProcessedEventsRepository>();

                    //-- Idempotency check --
                    //if this event id was already processed (e.g. Kafka replay after crash)
                    // skip processing but still commit so we don't get stuck replaying
                    var isAlreadyProcessed = await processedEventRepository.ExistsAsync(eventId, ct);
                    if (isAlreadyProcessed)
                    {
                        _logger.LogWarning("EventId {EventId} already processed. Skipping.",eventId);
                        consumer.Commit(result);
                        continue;
                    }

                    // --- Process the event ---
                    var existing = await inventoryRepository.GetByProductIdAsync(@event.ProductId, ct);
                    if (existing is not null)
                    {
                        _logger.LogWarning(
                            "Inventory item for ProductId {ProductId} already exists. Skipping.",
                            @event.ProductId);
                        consumer.Commit(result);
                        continue;
                    }

                    // Create InventoryItem with 1000 qty default for MVP
                    var item = InventoryItem.Create(@event.ProductId);
                    await inventoryRepository.AddAsync(item, ct);

                    // Mark the event as processed to avoid duplication
                    await processedEventRepository.AddAsync(eventId, ct);

                    _logger.LogInformation(
                    "Inventory item created for ProductId {ProductId}. EventId {EventId}.",
                    @event.ProductId,
                    eventId);

                    // Commit offset AFTER successful processing + EventId stored
                    // If we crash before this — Kafka replays the message
                    // but idempotency check catches the duplicate on next attempt
                    consumer.Commit(result);

                }
                catch (OperationCanceledException) 
                {
                    // Expected on app shutdown — exit loop cleanly
                    _logger.LogInformation("ProductCreatedConsumer is shutting down.");
                    break;
                }
                catch(Exception ex)
                {
                    // Unexpected error — log but don't commit
                    // Kafka will replay this message on next restart
                    _logger.LogError(ex, "Error processing ProductCreatedEvent.");
                }

            }

            // Release Kafka resources and trigger partition rebalance
            // so other consumers can take over this partition
            consumer.Close();

            _logger.LogInformation("ProductCreatedConsumer stopped.");


        }
    }
}
