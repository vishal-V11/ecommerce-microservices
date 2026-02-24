using Microsoft.AspNetCore.Identity;

namespace Identity.Api.Models
{
    public class ApplicationUser:IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string? Address { get; set; }
        public string? City { get; set; }
        public string? State { get; set; }
        public string? Country { get; set; }
        public string? ZipCode { get; set; }
        public ICollection<RefreshToken> RefreshTokens { get; set; }
    }
}
