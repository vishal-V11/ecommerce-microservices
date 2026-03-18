using Ordering.Application.Common.Security;

namespace Ordering.Application.Abstractions
{
    public interface IUserContext
    {
        CurrentUser User { get; }
    }
}
