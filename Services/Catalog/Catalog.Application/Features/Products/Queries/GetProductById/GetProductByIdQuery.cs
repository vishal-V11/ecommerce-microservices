using Catalog.Application.Common.DTO;
using MediatR;

namespace Catalog.Application.Features.Products.Queries.GetProductById
{
    public sealed record GetProductByIdQuery(Guid ProductId) 
        :IRequest<ProductDetailDto?>;
    
}
