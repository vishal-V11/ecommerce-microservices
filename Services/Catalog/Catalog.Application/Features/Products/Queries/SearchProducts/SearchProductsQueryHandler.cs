using Catalog.Application.Abstractions;
using Catalog.Application.Common.DTO;
using Catalog.Application.Common.Responses;
using MediatR;

namespace Catalog.Application.Features.Products.Queries.SearchProducts
{
    public sealed class SearchProductsQueryHandler : IRequestHandler<SearchProductsQuery, CursorResult<ProductSearchVm>>
    {
        private readonly IProductReadRepository _productRepository;
        public SearchProductsQueryHandler(IProductReadRepository productRepository)
        {
            _productRepository = productRepository;
        }
        public async Task<CursorResult<ProductSearchVm>> Handle(SearchProductsQuery request, CancellationToken ct)
        {
            var cursor = CursorDto.TryDecode(request.Cursor);
            var items = await _productRepository.SearchAsync(request, cursor, ct);

            // Fetch PageSize + 1 to check HasNextPage
            var hasNextPage = items.Count > request.PageSize;
            if (hasNextPage) items.RemoveAt(items.Count - 1);

            var nextCursor = hasNextPage ? new CursorDto { CreatedAt = items.Last().CreatedAt, ProductId = items.Last().ProductId }.Encode() : null;

            return new CursorResult<ProductSearchVm> { Items = items, NextCursor = nextCursor, HasNextPage = hasNextPage };
        }
    }
}
