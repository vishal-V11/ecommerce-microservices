namespace Catalog.Application.Common.Responses
{
    public sealed class PagedResult<T>
    {
        public bool IsSuccess { get; init; }

        public IReadOnlyList<T> Items { get; init; } = [];

        public int Page { get; init; }

        public int PageSize { get; init; }

        public long TotalCount { get; init; }

        public int TotalPages
            => (int)Math.Ceiling((double)TotalCount / PageSize);

        public string? Message { get; init; }

        public List<string>? Errors { get; init; }

        private PagedResult() { }

        public static PagedResult<T> Success(
            IReadOnlyList<T> items,
            int page,
            int pageSize,
            long totalCount)
            => new PagedResult<T>
            {
                IsSuccess = true,
                Items = items,
                Page = page,
                PageSize = pageSize,
                TotalCount = totalCount
            };

        public static PagedResult<T> Failure(List<string> errors)
            => new PagedResult<T>
            {
                IsSuccess = false,
                Errors = errors
            };
    }
}
