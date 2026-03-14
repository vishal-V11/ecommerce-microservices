using Cart.Application.Abstractions;
using Cart.Application.Common.DTOs;
using Cart.Application.Extensions;
using Cart.Domain.Exceptions;
using MediatR;

namespace Cart.Application.Features.Commands.IncrementItem
{
    public sealed class IncrementItemCommandHandler : IRequestHandler<IncrementItemCommand, CartDto>
    {
        private readonly IUserContext _userContext;
        private readonly ICartRepository _cartRepository;
        public IncrementItemCommandHandler(IUserContext userContext, ICartRepository cartRepository)
        {                             
            _userContext = userContext;
            _cartRepository = cartRepository;
        }
        public async Task<CartDto> Handle(IncrementItemCommand request, CancellationToken ct)
        {
            var userId = _userContext.User.UserId;

            var cart = await _cartRepository.GetCartAsync(userId, ct)
                ?? throw new CartNotFoundException(userId);

            cart.IncrementItem(request.ProductId, request.Quantity);

            await _cartRepository.SaveCartAsync(cart, ct);

            return cart.ToDto();
        }
    }
}
