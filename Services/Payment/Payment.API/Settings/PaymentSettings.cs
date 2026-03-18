using System.ComponentModel.DataAnnotations;

namespace Payment.API.Settings
{
    public sealed class PaymentSettings
    {
        public const string SectionName = "Payment";

        [Required]
        [Range(0.0, 1.0)]
        public double FailureRate { get; init; }
    }
}
