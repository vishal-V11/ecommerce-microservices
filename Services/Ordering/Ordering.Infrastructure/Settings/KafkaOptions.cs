using System.ComponentModel.DataAnnotations;

namespace Ordering.Infrastructure.Settings
{
    public class KafkaOptions
    {

        [Required]
        public string BootstrapServers { get; set; } = default!;
    }
}
