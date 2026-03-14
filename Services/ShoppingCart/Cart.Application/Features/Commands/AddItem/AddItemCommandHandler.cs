using Cart.Application.Abstractions;
using Cart.Application.Common.DTOs;
using Cart.Application.Extensions;
using MediatR;

namespace Cart.Application.Features.Commands.AddItem
{
    public sealed class AddItemCommandHandler : IRequestHandler<AddItemCommand, CartDto>
    {
        private IUserContext _userContext;
        private readonly ICartRepository _cartRepository;
        public AddItemCommandHandler(IUserContext userContext, ICartRepository cartRepository)
        {
            _userContext = userContext;
            _cartRepository = cartRepository;
        }

        public async Task<CartDto> Handle(AddItemCommand request, CancellationToken ct)
        {
            var userId = _userContext.User.UserId;

            var cart = await _cartRepository.GetCartAsync(userId, ct)
                ?? new Domain.Entities.Cart(userId);

            cart.AddItem(request.ProductId, request.ProductName, request.UnitPrice);

            await _cartRepository.SaveCartAsync(cart, ct);

            return cart.ToDto();
        }
    }
}
