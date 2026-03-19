using Confluent.Kafka;
using Microsoft.Extensions.Options;
using Payment.API.Abstraction;
using Payment.API.Settings;
using Shared.Messaging.Constants;
using Shared.Messaging.Events.Payment;
using System.Text.Json;

namespace Payment.API.Consumers
{
    public class PaymentProcessRequestedConsumer : BackgroundService
    {
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly KafkaSettings _kafkaSettings;
        private readonly PaymentSettings _paymentSettings;
        private readonly ILogger<PaymentProcessRequestedConsumer> _logger;

        public PaymentProcessRequestedConsumer(IServiceScopeFactory scopeFactory,
            IOptions<KafkaSettings> options,
            IOptions<PaymentSettings> paymentoptions,
            ILogger<PaymentProcessRequestedConsumer> logger
            )
        {
            _scopeFactory = scopeFactory;
            _kafkaSettings = options.Value;
            _paymentSettings = paymentoptions.Value;
            _logger = logger;
        }
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            var consumerConfig = new ConsumerConfig()
            {
                BootstrapServers = _kafkaSettings.BootstrapServers,

                // Identity of this consumer group
                // Kafka tracks offset independently per group
                // Multiple instances of this service share the same GroupId
                // Kafka distributes partitions across them automatically
                GroupId = KafkaGroups.PaymentService,

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

            var producerConfig = new ProducerConfig()
            {
                BootstrapServers = _kafkaSettings.BootstrapServers
            };

            using var consumer = new ConsumerBuilder<string, string>(consumerConfig).Build();
            using var producer = new ProducerBuilder<string, string>(producerConfig).Build();

            consumer.Subscribe(KafkaTopics.PaymentProcessRequested);

            _logger.LogInformation("Payment consumer started. FailureRate: {FailureRate}", _paymentSettings.FailureRate);

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var result = consumer.Consume(stoppingToken);
                    var @event = JsonSerializer.Deserialize<PaymentProcessRequestedEvent>(result.Message.Value);

                    if (@event is null)
                    {
                        _logger.LogWarning("Received null or undeserializable payment event. Skipping.");
                        consumer.Commit(result);
                        continue;
                    }

                    using (_logger.BeginScope(new Dictionary<string, object>
                    {
                        ["CorrelationId"] = @event.CorrelationId,
                        ["UserId"] = @event.UserId
                    }))
                    {
                        _logger.LogInformation("Payment event received");

                        using var scope = _scopeFactory.CreateAsyncScope();

                        var repository = scope.ServiceProvider.GetRequiredService<IPaymentRepository>();

                        var alreadyProcessed = await repository.ExistsAsync(@event.CorrelationId, stoppingToken);

                        if (alreadyProcessed)
                        {
                            _logger.LogWarning("Payment already processed. Skipping duplicate.");
                            consumer.Commit(result);
                            continue;
                        }

                        //Logic to simulate payment failure
                        var rng = new Random(@event.CorrelationId.GetHashCode());
                        var shouldFail = rng.NextDouble() < _paymentSettings.FailureRate;

                        if (shouldFail)
                        {
                            const string reason = "Simulated payment failure";

                            var payment = Entities.Payment.CreateFailed(@event.CorrelationId, @event.UserId, @event.Amount,@event.PaymentMethod, reason);

                            await repository.AddAsync(payment,stoppingToken);

                            //Produce Payment failed Message

                            var failedEvent = new PaymentFailedEvent(
                                @event.CorrelationId,
                                @event.UserId,
                                reason,
                                DateTimeOffset.UtcNow);

                            await producer.ProduceAsync(
                                KafkaTopics.PaymentFailed,
                                new Message<string, string>
                                {
                                    Key = @event.CorrelationId.ToString(),
                                    Value = JsonSerializer.Serialize(failedEvent)
                                },
                                stoppingToken);

                            _logger.LogInformation("Payment failed (simulated). Reason: {Reason}", reason);
                        }
                        else
                        {
                            var payment = Entities.Payment.CreateSucceeded(@event.CorrelationId, @event.UserId, @event.Amount,@event.PaymentMethod);
                            await repository.AddAsync(payment, stoppingToken);

                            var succeededEvent = new PaymentSucceededEvent(
                                @event.CorrelationId,
                                @event.UserId,
                                DateTime.UtcNow);

                            await producer.ProduceAsync(
                                KafkaTopics.PaymentSucceeded,
                                new Message<string, string>
                                {
                                    Key = @event.CorrelationId.ToString(),
                                    Value = JsonSerializer.Serialize(succeededEvent)
                                },
                                stoppingToken);

                            _logger.LogInformation("Payment succeeded.");
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
                    _logger.LogError(ex, "Unhandled error processing payment event.");
                }
            }

            consumer.Close();
        }
    }
}
