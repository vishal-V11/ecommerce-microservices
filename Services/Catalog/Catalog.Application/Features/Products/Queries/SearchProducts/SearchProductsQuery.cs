using Catalog.Application.Common.DTO;
using Catalog.Application.Common.Responses;
using MediatR;

namespace Catalog.Application.Features.Products.Queries.SearchProducts
{
    public sealed record SearchProductsQuery(
    string? Search = null,
    Guid? CategoryId = null,
    Guid? BrandId = null,
    decimal? MinPrice = null,
    decimal? MaxPrice = null,
    string? Cursor = null,  // Base64 encoded CursorDto
    int PageSize = 20
) : IRequest<CursorResult<ProductSearchVm>>;
}
