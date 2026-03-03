using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Catalog.Infrastructure.Messaging.Producers.Kafka
{
    public class KafkaSettings
    {
        public string BootstrapServers { get; set; } = default!;
    }
}
