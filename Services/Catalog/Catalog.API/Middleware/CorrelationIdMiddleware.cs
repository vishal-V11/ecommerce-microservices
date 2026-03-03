using Microsoft.Net.Http.Headers;

namespace Catalog.API.Middleware
{
    public class CorrelationIdMiddleware
    {
        public readonly RequestDelegate _next;
        private const string CorrelationIdHeader = "X-Correlation-Id";
        private readonly ILogger<CorrelationIdMiddleware> _logger;

        public CorrelationIdMiddleware(RequestDelegate next, ILogger<CorrelationIdMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var correlationId = context.Request.Headers[CorrelationIdHeader].FirstOrDefault()
                                ?? Guid.NewGuid().ToString();

            context.TraceIdentifier = correlationId;

            using (_logger.BeginScope(
                new Dictionary<string, object>
                {
                    ["CorrelationId"] = correlationId
                }))
            {
                context.Response.Headers[CorrelationIdHeader] = correlationId;
                await _next(context);
            }


        }
    }
}
