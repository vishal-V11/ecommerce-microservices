using Cart.Application.Common.DTOs;
using MediatR;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cart.Application.Features.Commands.RemoveItemCart
{
    public record RemoveItemCommand
    (
        Guid ProductId

    ) : IRequest<CartDto>;
}
