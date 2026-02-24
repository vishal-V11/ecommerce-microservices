namespace Identity.Api.Helpers
{
    public record JwtUserInfo
    {
        public string UserId { get; init; }
        public string Role { get; init; } = "User";
        public string Email { get; init; }
        public string UserName { get; init; }
    }
}
