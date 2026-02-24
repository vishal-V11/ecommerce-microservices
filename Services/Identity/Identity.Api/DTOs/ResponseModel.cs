namespace Identity.Api.DTOs
{
    public class Response<T> where T : class
    {
        /// <summary>
        /// Indicates whether the operation was successful
        /// </summary>

        public bool Succeeded { get; set; }

        /// <summary>
        /// The response message you want to set 
        /// </summary>
        public string? Message { get; set; }
        public string? Error { get; set; }
        public int StatusCode { get; set; }
        public T? ResponseData { get; set; }

        // Factory methods for convenience
        public static Response<T> Success(T? data, string? message = null, int statusCode = 200)
            => new Response<T>
            {
                Succeeded = true,
                ResponseData = data,
                Message = message,
                StatusCode = statusCode
            };

        public static Response<T> Fail(string? errorMessage, string? message = null, int statusCode = 400)
            => new Response<T>
            {
                Succeeded = false,
                Error = errorMessage,
                Message = message,
                StatusCode = statusCode
            };
    }
}
