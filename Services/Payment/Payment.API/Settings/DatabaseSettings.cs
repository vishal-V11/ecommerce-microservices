using System.ComponentModel.DataAnnotations;

namespace Payment.API.Settings
{
    public class DatabaseSettings
    {

        [Required]
        public string ConnectionString { get; set; } = default!;

    }
}
