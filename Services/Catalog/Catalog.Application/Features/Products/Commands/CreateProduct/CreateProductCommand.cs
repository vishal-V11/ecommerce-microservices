using Catalog.Application.Common.Responses;
using MediatR;

namespace Catalog.Application.Features.Products.Commands.CreateProduct
{
    public record CreateProductCommand(

        string Name,
        string Description,
        decimal Price,
        Guid BrandId,
        Guid CategoryId,
        string ImageUrl,
        bool IsActive
        ) : IRequest<Result<Guid>>;
     
    
}
