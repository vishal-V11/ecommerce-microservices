using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc.Filters;
using System.Net;

namespace Identity.Api.Middleware
{
    public class GlobalExceptionHandling 
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<GlobalExceptionHandling> _logger;
        public GlobalExceptionHandling(RequestDelegate next, ILogger<GlobalExceptionHandling> logger)
        {
            _next = next;
            _logger = logger;
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


        public async Task HandleExceptionAsync(HttpContext context,Exception ex)
        {
            var response = new ErrorResponse();
            context.Response.ContentType = "application/json";

            switch (ex)
            {
                case ArgumentException:
                    response.StatusCode = (int)HttpStatusCode.BadRequest;
                    response.Message = "";
                    response.Error = ex.Message;
                    break;
                case KeyNotFoundException:
                    response.StatusCode = (int)HttpStatusCode.NotFound;
                    response.Message = "";
                    response.Error = ex.Message;
                    break;
                case UnauthorizedAccessException:
                    response.StatusCode = (int)HttpStatusCode.Unauthorized;
                    response.Message = "Unauthorized";
                    response.Error = ex.Message;
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


    }

    public class ErrorResponse
    {
        public int StatusCode { get; set; }

        public string Message { get; set; } = string.Empty;

        public string? Error { get; set; }

        public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;


    }
}
