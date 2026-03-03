using Catalog.Application.Abstractions;

namespace Catalog.API.Context
{
    public class CorrelationContext : ICorrelationContext
    {
        private readonly IHttpContextAccessor _accessor;
        public CorrelationContext(IHttpContextAccessor accessor)
        {
            _accessor = accessor;
        }
        public string CorrelationId 
            => _accessor.HttpContext?.TraceIdentifier ?? string.Empty;
    }
}
