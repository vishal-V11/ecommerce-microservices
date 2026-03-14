namespace Cart.API.Middleware
{
    /// <summary>
    /// Extension methods to add Custom Middlewares
    /// </summary>
    public static class MiddleExtensions
    {
        public static IApplicationBuilder UseGlobalExceptionHandler(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<ExceptionHandlingMiddleware>();
        }

        public static IApplicationBuilder UseCorrelationId(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<CorrelationIdMiddleware>();
        }

        /// <summary>
        /// /// Adds all custom middleware to the pipeline in the recommended order
        /// </summary>
        public static IApplicationBuilder UseCustomMiddleware(this IApplicationBuilder builder)
        {
            //Order Sequence matters here

            //1 Add the correlation middleware
            builder.UseCorrelationId();

            //2 Add Global exception Handling Middleware
            builder.UseGlobalExceptionHandler();

            return builder;
        }
    }
}
