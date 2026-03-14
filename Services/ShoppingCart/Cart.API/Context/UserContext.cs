using Cart.Application.Abstractions;
using Cart.Application.Common.Security;
using System.Security.Claims;

namespace Cart.API.Context
{
    public sealed class UserContext : IUserContext
    {
        private readonly IHttpContextAccessor _accessor;
        public UserContext(IHttpContextAccessor accessor)
        {
            _accessor = accessor;
        }
        public CurrentUser User
        {
            get
            {
                var principal = _accessor.HttpContext?.User;
                if (principal?.Identity?.IsAuthenticated != true)
                    return new CurrentUser { IsAuthenticated = false };
                return new CurrentUser
                {
                    UserId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value!,
                    Email = principal.FindFirst(ClaimTypes.Email)?.Value,
                    //Roles = principal.FindAll(ClaimTypes.Role)
                    //                 .Select(r => r.Value)
                    //                 .ToList(),
                    IsAuthenticated = true
                };
            }
        }
    }
}
