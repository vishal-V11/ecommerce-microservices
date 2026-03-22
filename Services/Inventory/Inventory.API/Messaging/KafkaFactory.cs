using Confluent.Kafka;
using Inventory.API.Settings;
using Microsoft.Extensions.Options;
using Shared.Messaging.Constants;

namespace Inventory.API.Messaging
{
    public sealed class KafkaFactory:IDisposable
    {
        private readonly KafkaSettings _kafkaSettings;
        private IProducer<string, string>? _producer;

        public KafkaFactory(IOptions<KafkaSettings> kafkaOptions)
        {
            _kafkaSettings = kafkaOptions.Value;
        }

        /// <summary>
        /// Creates a producer builder instances, reuse if already exists
        /// </summary>
        /// <returns></returns>
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

        /// <summary>
        /// Creates a consumer builder instance and returns it
        /// </summary>
        /// <param name="groupId">Kafka Group Id</param>
        /// <returns></returns>
        public IConsumer<string, string> CreateConsumer(string groupId)
        {
            var config = new ConsumerConfig
            {
                BootstrapServers = _kafkaSettings.BootstrapServers,

                // Identity of this consumer group
                // Kafka tracks offset independently per group
                // Multiple instances of this service share the same GroupId
                // Kafka distributes partitions across them automatically
                GroupId = groupId,

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
            return new ConsumerBuilder<string, string>(config).Build();
        }

        public void Dispose() => _producer?.Dispose();
    }
}
