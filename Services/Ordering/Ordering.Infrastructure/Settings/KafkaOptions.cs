using System.ComponentModel.DataAnnotations;

namespace Ordering.Infrastructure.Settings
{
    public class KafkaOptions
    {
        public const string SectionName = "kafka";

        [Required]
        public string BootstrapServers { get; init; } = default!;
    }
}
