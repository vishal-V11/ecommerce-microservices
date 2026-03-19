using Cart.Domain.Exceptions;

namespace Cart.API.Middleware
{
    public class ExceptionHandlingMiddleware
    {
        private readonly ILogger<ExceptionHandlingMiddleware> _logger;
        private readonly RequestDelegate _next;
        private readonly IHostEnvironment _environment;

        public ExceptionHandlingMiddleware(ILogger<ExceptionHandlingMiddleware> logger,
            RequestDelegate next, 
            IHostEnvironment environment)
        {
            _logger = logger;
            _next = next;
            _environment = environment;
        }

        public async Task InvokeAsync(HttpContext context, RequestDelegate next)
        {
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unhandled exception occured while processing the request");
                await HandleExceptionAsync(context, ex);
            }
        }

        private async Task HandleExceptionAsync(HttpContext context, Exception exception)
        {
            var response = new ErrorResponse()
            {
                TraceId = context.TraceIdentifier,
            };

            context.Response.ContentType = "application/json";

            switch (exception)
            {
                case CartNotFoundException:
                case CartItemNotFoundException:
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    response.StatusCode = StatusCodes.Status404NotFound;
                    response.Error = exception.Message;
                    response.Message = exception.Message;
                    break;
                case ArgumentException:
                    context.Response.StatusCode = StatusCodes.Status400BadRequest;
                    response.StatusCode = StatusCodes.Status400BadRequest;
                    response.Error = exception.Message;
                    response.Message = "Invalid request";
                    break;
                default:
                    context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                    response.StatusCode = StatusCodes.Status500InternalServerError;
                    response.Message = "Internal server error";

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
}
