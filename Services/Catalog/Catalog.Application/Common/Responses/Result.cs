namespace Catalog.Application.Common.Responses
{
    public sealed class Result<T>
    {
        public bool IsSuccess { get; init; }

        public T? Data { get; init; }

        public string? Message { get; init; }

        public List<string>? Errors { get; init; }

        private Result() { }

        public static Result<T> Success(T data, string? message = null)
            => new Result<T>
            {
                IsSuccess = true,
                Data = data,
                Message = message
            };

        public static Result<T> Failure(List<string> errors, string? message = null)
            => new Result<T>
            {
                IsSuccess = false,
                Errors = errors,
                Message = message
            };
    }
}
