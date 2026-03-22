using Catalog.Infrastructure.Settings;
using Confluent.Kafka;
using Microsoft.Extensions.Options;

namespace Catalog.Infrastructure.Messaging
{
    public class KafkaFactory:IDisposable 
    {
        private readonly KafkaSettings _kafkaSettings;
        private IProducer<string, string>? _producer;

        public KafkaFactory(IOptions<KafkaSettings> kafkaOptions)
        {
            _kafkaSettings = kafkaOptions.Value;
        }

        public IProducer<string, string> CreateProducer()
        {
            _producer ??= new ProducerBuilder<string, string>(new ProducerConfig
            {
                BootstrapServers = _kafkaSettings.BootstrapServers,
                Acks = Acks.All,
                EnableIdempotence = true
            }).Build();

            return _producer;
        }

        //public IConsumer<string, string> CreateConsumer(string groupId)
        //{
        //    var config = new ConsumerConfig
        //    {
        //        BootstrapServers = _settings.BootstrapServers,
        //        GroupId = groupId,
        //        AutoOffsetReset = AutoOffsetReset.Earliest,
        //        EnableAutoCommit = false
        //    };
        //    return new ConsumerBuilder<string, string>(config).Build();
        //}

        public void Dispose() => _producer?.Dispose();
    }
}
