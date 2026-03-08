using Catalog.Application.Common.Responses;
using MediatR;

namespace Catalog.Application.Features.Products.Commands.UpdateProduct
{
    public sealed record UpdateProductCommand(
        Guid ProductId,
        string Name,
        string? Description,
        decimal Price,
        Guid BrandId,
        Guid CategoryId,
        string ImagePath
    ) : IRequest<Result>;
}
