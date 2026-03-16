using Catalog.Application.Abstractions;
using Confluent.Kafka;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Text;

namespace Catalog.Infrastructure.Messaging.Producers.Kafka
{
    public class KafkaIntegrationEventPublisher : IIntegrationEventPublisher
    {
        private readonly IProducer<string, string> _producer;
        private readonly ILogger<KafkaIntegrationEventPublisher> _logger;

        public KafkaIntegrationEventPublisher(
            IProducer<string, string> producer,
            ILogger<KafkaIntegrationEventPublisher> logger)
        {
            _producer = producer;
            _logger = logger;
        }

        public async Task PublishAsync(
            string topic,
            string key,
            string payload,
            IDictionary<string, string>? headers = null,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var message = new Message<string, string>
                {
                    Key = key,
                    Value = payload
                };

                // Add Kafka headers if provided
                if (headers is not null && headers.Count > 0)
                {
                    message.Headers = new Headers();

                    foreach (var header in headers)
                    {
                        message.Headers.Add(
                            header.Key,
                            Encoding.UTF8.GetBytes(header.Value));
                    }
                }

                var result = await _producer.ProduceAsync(
                    topic,
                    message,
                    cancellationToken);

                _logger.LogInformation(
                    "Kafka message published successfully. Topic: {Topic}, Key: {Key}, Partition: {Partition}, Offset: {Offset}",
                    topic,
                    key,
                    result.Partition,
                    result.Offset);
            }
            catch (ProduceException<string, string> ex)
            {
                _logger.LogError(
                    ex,
                    "Kafka produce error. Topic: {Topic}, Key: {Key}, Error: {Reason}",
                    topic,
                    key,
                    ex.Error.Reason);

                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "Unexpected error while publishing Kafka message. Topic: {Topic}, Key: {Key}",
                    topic,
                    key);

                throw;
            }
        }
    }
}
