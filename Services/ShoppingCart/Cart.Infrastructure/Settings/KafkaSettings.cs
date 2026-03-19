using System.ComponentModel.DataAnnotations;

namespace Cart.Infrastructure.Settings
{
    public class KafkaSettings
    {
        [Required]
        public string BootstrapServers { get; set; } = default!;
    }
}
