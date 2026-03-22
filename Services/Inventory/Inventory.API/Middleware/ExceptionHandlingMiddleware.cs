using Inventory.API.Exceptions;
using System.Linq.Expressions;
using System.Net;

namespace Inventory.API.Middleware
{
    public class ExceptionHandlingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ExceptionHandlingMiddleware> _logger;
        private readonly IHostEnvironment _environment;

        public ExceptionHandlingMiddleware(ILogger<ExceptionHandlingMiddleware> logger,
            RequestDelegate next,
            IHostEnvironment environment)
        {
            _logger = logger;
            _next = next;
            _environment = environment;
        }

        public async Task InvokeAsync(HttpContext context)
        {

            try
            {
                await _next(context);
            }
            catch(Exception ex)
            {
                _logger.LogWarning("Some unexpected error occured");

                await HandleExceptionAsync(context, ex);
            }
        }

        private async Task HandleExceptionAsync(HttpContext context, Exception exception)
        {
            context.Response.ContentType = "application/json";
            var response = new ErrorResponse()
            {
                TraceId = context.TraceIdentifier,
            };
            switch (exception)
            {
                case InsufficientStockException:
                    response.StatusCode = (int)HttpStatusCode.InsufficientStorage;
                    response.Error = exception.Message;
                    response.Message = "Inventory Item not found";
                    break;

                case InventoryItemNotFoundException:
                    response.StatusCode = (int)HttpStatusCode.NotFound;
                    response.Error = exception.Message;
                    response.Message = "Inventory Item not found";
                    break;
                default:
                    response.StatusCode = (int)HttpStatusCode.InternalServerError;
                    response.Error = exception.Message;
                    response.Message = "An internal server error occurred";

                    // Only include detailed error in development
                    response.Error = _environment.IsDevelopment()
                        ? exception.Message
                        : "An error occurred while processing your request";

                    if (_environment.IsDevelopment())
                    {
                        response.StackTrace = exception.StackTrace;
                    }

                    break;
            } 
        }
    }

    public class ErrorResponse
    {
        public int StatusCode { get; set; }
        public string Message { get; set; } = string.Empty;
        public string? Error { get; set; }
        public string? StackTrace { get; set; }
        public string TraceId { get; set; } = string.Empty;
        public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;


    }
}
