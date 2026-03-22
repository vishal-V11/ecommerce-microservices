using System.ComponentModel.DataAnnotations;

namespace Ordering.Infrastructure.Settings
{
    public sealed class DatabaseOptions
    {
        [Required]
        public string Postgres { get; set; } = default!;
    }
}
