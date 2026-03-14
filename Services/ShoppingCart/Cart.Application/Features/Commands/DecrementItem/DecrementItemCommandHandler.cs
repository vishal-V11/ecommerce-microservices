using Cart.Application.Abstractions;
using Cart.Application.Common.DTOs;
using Cart.Application.Extensions;
using Cart.Domain.Exceptions;
using MediatR;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cart.Application.Features.Commands.DecrementItem
{
    public sealed class DecrementItemCommandHandler : IRequestHandler<DecrementItemCommand, CartDto>
    {
        private readonly IUserContext _userContext;
        private readonly ICartRepository _cartRepository;

        public DecrementItemCommandHandler(IUserContext userContext,ICartRepository cartRepository)
        {
            _cartRepository = cartRepository;
            _userContext = userContext;
        }

        public async Task<CartDto> Handle(DecrementItemCommand request, CancellationToken ct)
        {
            var userId = _userContext.User.UserId;
            var cart = await _cartRepository.GetCartAsync(userId, ct)
                ?? throw new CartNotFoundException(userId);

            cart.DecrementItem(request.ProductId, request.Quantity);

            await _cartRepository.SaveCartAsync(cart, ct);

            return cart.ToDto();
        }
    }
}
