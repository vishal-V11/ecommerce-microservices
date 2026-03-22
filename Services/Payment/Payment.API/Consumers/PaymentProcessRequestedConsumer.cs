using Confluent.Kafka;
using Microsoft.Extensions.Options;
using Payment.API.Abstraction;
using Payment.API.Messaging;
using Payment.API.Settings;
using Shared.Messaging.Constants;
using Shared.Messaging.Events.Payment;
using System.Text.Json;

namespace Payment.API.Consumers
{
    public class PaymentProcessRequestedConsumer : BackgroundService
    {
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly KafkaFactory _kafkaFactory;
        private readonly PaymentSettings _paymentSettings;
        private readonly ILogger<PaymentProcessRequestedConsumer> _logger;

        public PaymentProcessRequestedConsumer(IServiceScopeFactory scopeFactory,
            KafkaFactory kafkaFactory,
            IOptions<PaymentSettings> paymentoptions,
            ILogger<PaymentProcessRequestedConsumer> logger
            )
        {
            _scopeFactory = scopeFactory;
            _kafkaFactory = kafkaFactory;
            _paymentSettings = paymentoptions.Value;
            _logger = logger;
        }
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {

            using var consumer = _kafkaFactory.CreateConsumer(KafkaGroups.PaymentService);
            var producer = _kafkaFactory.CreateProducer();

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
