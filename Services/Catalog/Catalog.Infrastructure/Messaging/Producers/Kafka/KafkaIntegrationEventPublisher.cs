using Catalog.Application.Abstractions;
using Confluent.Kafka;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Catalog.Infrastructure.Messaging.Producers.Kafka
{
    public class KafkaIntegrationEventPublisher : IIntegrationEventPublisher
    {

        private readonly IProducer<string, string> _producer;

        public KafkaIntegrationEventPublisher(IOptions<KafkaSettings> settings)
        {
            var config = new ProducerConfig
            {
                BootstrapServers = settings.Value.BootstrapServers
            };

            _producer = new ProducerBuilder<string, string>(config).Build();
        }
        public async Task PublishAsync(string topic,string payload,CancellationToken cancellationToken = default)
        {
            await _producer.ProduceAsync(topic, new Message<string, string>
            {
                Key = Guid.NewGuid().ToString(),
                Value = payload
            }, cancellationToken);
        }
    }
}
