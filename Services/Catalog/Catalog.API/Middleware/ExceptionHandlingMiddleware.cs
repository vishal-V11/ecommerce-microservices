using Catalog.Application.Exceptions;
using Microsoft.AspNetCore.Http.HttpResults;

namespace Catalog.API.Middleware
{
    public class ExceptionHandlingMiddleware
    {
        private readonly ILogger<ExceptionHandlingMiddleware> _logger;
        private readonly RequestDelegate _next;

        public ExceptionHandlingMiddleware(ILogger<ExceptionHandlingMiddleware> logger, RequestDelegate next)
        {
            _logger = logger;
            _next = next;
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
                await HandleExceptionAsync(context, ex);
            }
        }

        public async Task HandleExceptionAsync(HttpContext context,Exception exception)
        {
            var response = new ErrorResponse();

            context.Response.ContentType = "application/json";

            switch (exception)
            {
                case NotFoundException:
                case KeyNotFoundException:
                    response.StatusCode = StatusCodes.Status404NotFound;
                    response.Message = "Resource not found";
                    response.Error = exception.Message;
                    break;

                case ArgumentException:
                case InvalidOperationException:
                    response.StatusCode = StatusCodes.Status400BadRequest;
                    response.Message = "Invalid request";
                    response.Error = exception.Message;
                    break;

                default:
                    response.StatusCode = StatusCodes.Status500InternalServerError;
                    response.Message = "Internal server error";
                    response.Error = "Something went wrong.";
                    break;

            }

            context.Response.StatusCode = response.StatusCode;
            await context.Response.WriteAsJsonAsync(response);

        }

        public class ErrorResponse
        {
            public int StatusCode { get; set; }

            public string Message { get; set; } = string.Empty;

            public string? Error { get; set; }

            public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;


        }

    }
}
