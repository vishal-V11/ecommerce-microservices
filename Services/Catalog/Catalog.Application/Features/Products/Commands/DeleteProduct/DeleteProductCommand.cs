using Catalog.Application.Common.Responses;
using MediatR;

namespace Catalog.Application.Features.Products.Commands.DeleteProduct
{
    public record DeleteProductCommand(Guid ProductId) : IRequest<Result>;
    
}
