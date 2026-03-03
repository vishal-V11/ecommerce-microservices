namespace Identity.Api.Settings
{
    public class JwtSettings
    {
        public string SecretKey { get; set; }

        public string Issuer { get; set; }
        public string Audience { get; set; }
        public double DurationInMinutes { get; set; }
        public double RefreshTokenExpiryInDays { get; set; }
    }
}
