using Identity.Api.Models;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Identity.Api.Models
{
    public class RefreshToken
    {
        public int Id { get; set; }

        //Store HASH of refresh token only
        [Required]
        public string TokenHash { get; set; }

        // Token lifetime
        public DateTimeOffset Expires { get; set; }
        public DateTimeOffset Created { get; set; } = DateTimeOffset.UtcNow;
        public DateTimeOffset? Revoked { get; set; }
        public DateTimeOffset? LastUsed { get; set; }

        // Session / device fingerprint
        [MaxLength(45)]
        public string CreatedByIp { get; set; }

        [MaxLength(500)]
        public string UserAgent { get; set; }

        [MaxLength(100)]
        public string Device { get; set; }
        [MaxLength(36)]
        public string DeviceId { get; set; }

        [Required]
        public string UserId { get; set; }
        public ApplicationUser User { get; set; }

        // Helper properties (not mapped to DB)
        [NotMapped]
        public bool IsExpired => DateTimeOffset.UtcNow >= Expires;

        [NotMapped]
        public bool IsActive => Revoked == null && !IsExpired;
    }
}
