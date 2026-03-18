namespace Ordering.Application.Common.Security
{
    public class CurrentUser
    {
        public string UserId { get; init; } = default!;
        public string? Email { get; init; }
        //public IReadOnlyCollection<string> Roles { get; init; } = Array.Empty<string>();
        public bool IsAuthenticated { get; init; }
    }
}
