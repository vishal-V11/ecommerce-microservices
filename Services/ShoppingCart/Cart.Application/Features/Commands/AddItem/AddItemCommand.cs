using Cart.Application.Common.DTOs;
using MediatR;

namespace Cart.Application.Features.Commands.AddItem
{
    public record AddItemCommand
    (
        Guid ProductId,
        string ProductName,
        decimal UnitPrice
    ) : IRequest<CartDto>;

}
