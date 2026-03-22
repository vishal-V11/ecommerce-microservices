using Catalog.Application.Abstractions;
using Catalog.Application.Common.Outbox;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Polly;
using Polly.Registry;

namespace Catalog.Infrastructure.Background
{
    /// <summary>A Background service job that publishes ProductCreated Event to kafka</summary>
    public class OutboxProcessor : BackgroundService
    {
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly ILogger<OutboxProcessor> _logger;
        private readonly ResiliencePipeline _pipeline;
        private const int MaxOutboxRetries = 3;
        public OutboxProcessor(IServiceScopeFactory scopeFactory
            , ResiliencePipelineProvider<string> resiliencePipelineProvider
            , ILogger<OutboxProcessor> logger)
        {
            _scopeFactory = scopeFactory;
            _logger = logger;
            _pipeline = resiliencePipelineProvider.GetPipeline("kafka-publish-pipeline");
            
        }
        protected async override Task ExecuteAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                _logger.LogInformation("Outbox pattern background service inititated");

                await ProcessBatchAsync(cancellationToken);

                await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken);

            }
        }

        private async Task ProcessBatchAsync(CancellationToken ct)
        {
            using var scope = _scopeFactory.CreateAsyncScope();

            var outboxRepository = scope.ServiceProvider.GetRequiredService<IOutboxRepository>();
            var publisher = scope.ServiceProvider.GetRequiredService<IIntegrationEventPublisher>();

            var messages = await outboxRepository.GetUnprocessedAsync(50, ct);

            foreach (var message in messages)
            {
                await ProcessMessageAsync(message, publisher, outboxRepository, ct);
            }
        }

        private async Task ProcessMessageAsync(OutboxMessage message
            ,IIntegrationEventPublisher publisher
            ,IOutboxRepository outboxRepository,CancellationToken cancellationToken)
        {
            try
            {
                await _pipeline.ExecuteAsync(async token =>
                {
                    await publisher.PublishAsync(
                    message.Topic,
                    message.EventId.ToString(),
                    message.Payload,
                    new Dictionary<string, string>
                        {
                            { "X-Correlation-Id", message.CorrelationId }
                        },
                    token
                    );
                }, cancellationToken);

                await outboxRepository.MarkAsProcessedAsync(
                   message.EventId,
                   DateTime.UtcNow,
                   cancellationToken);

                _logger.LogInformation(
                    "Outbox event {EventId} published to topic {Topic}",
                    message.EventId,
                    message.Topic);
            }
            catch (Exception ex)
            {
                
                _logger.LogError(
                    ex,
                    "Failed to publish event {EventId} after retries",
                    message.EventId);

                await outboxRepository.RecordFailureAsync(
                    message.EventId,
                    ex.Message,
                    cancellationToken);
            }

        }
    }
}
