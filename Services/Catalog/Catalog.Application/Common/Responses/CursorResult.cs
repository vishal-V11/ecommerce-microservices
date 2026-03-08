namespace Catalog.Application.Common.Responses
{
    public sealed class CursorResult<T>
    {
        public IReadOnlyList<T> Items { get; init; } = [];
        public bool HasNextPage { get; init; }
        public string? NextCursor { get; init; }
    }
}
