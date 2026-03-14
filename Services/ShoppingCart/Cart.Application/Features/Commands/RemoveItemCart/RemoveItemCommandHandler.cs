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

namespace Cart.Application.Features.Commands.RemoveItemCart
{
    public sealed class RemoveItemCommandHandler:IRequestHandler<RemoveItemCommand, CartDto>
    {
        private readonly IUserContext _userContext;
        private readonly ICartRepository _cartRepository;

        public RemoveItemCommandHandler(IUserContext userContext,ICartRepository cartRepository)
        {
            _userContext = userContext;
            _cartRepository = cartRepository;
        }
        public async Task<CartDto> Handle(RemoveItemCommand request, CancellationToken ct)
        {
            var userId = _userContext.User.UserId;

            var cart = await _cartRepository.GetCartAsync(userId, ct)
                ?? throw new CartNotFoundException(userId);

            cart.RemoveItem(request.ProductId);

            await _cartRepository.SaveCartAsync(cart, ct);

            return cart.ToDto();
        }
    }
}
