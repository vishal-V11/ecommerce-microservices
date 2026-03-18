using Ordering.Application.Abstractions;
using Ordering.Application.Common.Security;
using System.Security.Claims;

namespace Ordering.API.Context
{
    public class UserContext : IUserContext
    {
        private readonly IHttpContextAccessor _contextAccessor;

        public UserContext(IHttpContextAccessor httpContext)
        {
            _contextAccessor = httpContext;
        }

        public CurrentUser User
        {
            get
            {
                var principal = _contextAccessor.HttpContext?.User;

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
