using Catalog.Application.Common.Responses;
using MediatR;

namespace Catalog.Application.Features.Products.Commands.SetProductActive
{
    public sealed record SetProductActiveCommand(
        Guid ProductId,
        bool IsActive
        ) : IRequest<Result>;
}
