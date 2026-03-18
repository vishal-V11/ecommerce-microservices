using System.ComponentModel.DataAnnotations;

namespace Ordering.Infrastructure.Settings
{
    public sealed class DatabaseOptions
    {
        public const string SectionName = "ConnectionStrings";

        [Required]
        public string Postgres { get; init; } = default!;
    }
}
