using System.ComponentModel.DataAnnotations;

namespace Payment.API.Settings
{
    public class DatabaseSettings
    {
        public const string SectionName = "ConnectionStrings";

        [Required]
        public string ConnectionString { get; init; } = default!;

    }
}
