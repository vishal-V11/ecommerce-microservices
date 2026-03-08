using Catalog.Application.Common.DTO;
using Catalog.Application.Common.Responses;
using MediatR;

namespace Catalog.Application.Features.Products.Queries.SearchProducts
{
    public sealed record GetProductListQuery(
         string? ProductName = null,
         Guid? BrandId = null,
         Guid? CategoryId = null,
         bool? IsActive = null,
         int PageNumber = 1,
         int PageSize = 20
    ) : IRequest<PagedResult<ProductListVm>>;

}
