using Catalog.Application.Common.DTO;
using Catalog.Application.Common.Responses;
using Catalog.Application.Features.Products.Queries.SearchProducts;

namespace Catalog.Application.Abstractions
{
    public interface IProductReadRepository
    {
        Task<ProductDetailDto?> GetByIdAsync(Guid id, CancellationToken ct);
        Task<PagedResult<ProductListVm>> GetPagedAsync(GetProductListQuery request, CancellationToken ct);
        Task<List<ProductSearchVm>> SearchAsync(SearchProductsQuery query,CursorDto? cursor, CancellationToken ct);
    }
}
