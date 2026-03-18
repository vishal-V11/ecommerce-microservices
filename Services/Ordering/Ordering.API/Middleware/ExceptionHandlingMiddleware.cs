using MassTransit;
using Ordering.Domain.Exceptions;
using System.Net;
using System.Text.Json;

namespace Ordering.API.Middleware
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

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unhandled exception occurred while processing the request");
                await HandleExceptionAsync(context,ex);
            }
        }

        private async Task HandleExceptionAsync(HttpContext context,Exception exception)
        {
            context.Response.ContentType = "application/json";
            var response = new ErrorResponse()
            {
                TraceId = context.TraceIdentifier,
            };

            switch (exception)
            {
                case OrderNotFoundException:
                    response.StatusCode = (int)HttpStatusCode.NotFound;
                    response.Error = exception.Message;
                    response.Message = "Order Not found";
                    break;
                case InvalidOrderStatusTransitionException:
                    response.StatusCode = (int)HttpStatusCode.Conflict;
                    response.Error = exception.Message;
                    response.Message = "Conflict of state";
                    break;
                case UnauthorizedAccessException:
                    response.StatusCode = (int)HttpStatusCode.Conflict;
                    response.Error = exception.Message;
                    response.Message = "Unauthorized access";
                    break;

                case ArgumentNullException _:
                case ArgumentException _:
                    context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                    response.StatusCode = (int)HttpStatusCode.BadRequest;
                    response.Message = "Invalid request";
                    response.Error = exception.Message;
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

            var jsonResponse = JsonSerializer.Serialize(response, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });

            await context.Response.WriteAsync(jsonResponse);
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
