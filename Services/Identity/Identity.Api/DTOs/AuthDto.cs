using System.ComponentModel.DataAnnotations;

namespace Identity.Api.DTOs
{
    public record RegisterRequestDto
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        [StringLength(256, ErrorMessage = "Email must not exceed 256 characters")]
        public required string Email { get; set; }

        [Required(ErrorMessage = "First name is required")]
        [StringLength(50, MinimumLength = 2, ErrorMessage = "First name must be between 2 and 50 characters")]
        [RegularExpression(@"^[a-zA-Z\s\-']+$", ErrorMessage = "First name contains invalid characters")]
        public required string FirstName { get; set; }

        [Required(ErrorMessage = "Last name is required")]
        [StringLength(50, MinimumLength = 2, ErrorMessage = "Last name must be between 2 and 50 characters")]
        [RegularExpression(@"^[a-zA-Z\s\-']+$", ErrorMessage = "Last name contains invalid characters")]
        public required string LastName { get; set; }

        [Required(ErrorMessage = "Password is required")]
        [StringLength(100, MinimumLength = 8, ErrorMessage = "Password must be between 8 and 100 characters")]
        [RegularExpression(
             @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&^#\-_])[A-Za-z\d@$!%*?&^#\-_]{8,}$",
             ErrorMessage = "Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character")]
        public required string Password { get; set; }

        [Required(ErrorMessage = "Confirm password is required")]
        [Compare(nameof(Password), ErrorMessage = "Passwords do not match")]
        public required string ConfirmPassword { get; set; }
    }

    /// <summary>
    /// Request DTO for user login
    /// </summary>
    public record LoginRequestDto
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        [StringLength(256, ErrorMessage = "Email must not exceed 256 characters")]
        public required string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password is required")]
        public required string Password { get; set; } = string.Empty;
    }

    public record RegisterResponseDto
    {
        public required string UserId { get; set; }
        public required string Email { get; set; }
        public required string FullName { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
    }

    public record TokenResponseDto
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public DateTimeOffset ExpiryTime { get; set; }

    }

    public record RefreshRequestDto
    {

        [Required(ErrorMessage = "Refresh Token is required")]
        public required string RefreshToken { get; set; }

    }
    public record LogoutRequestDto
    {

        [Required(ErrorMessage = "Refresh Token is required")]
        public required string RefreshToken { get; set; }

    }




}
