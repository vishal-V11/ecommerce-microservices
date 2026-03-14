using Cart.Application.Abstractions;
using Cart.Domain.Exceptions;
using MediatR;
namespace Cart.Application.Features.Commands.ClearCart
{
    public sealed class ClearCartCommandHandler : IRequestHandler<ClearCartCommand>
    {
        private readonly IUserContext _userContext;
        private readonly ICartRepository _cartRepository;
        public ClearCartCommandHandler(IUserContext userContext, ICartRepository cartRepository)
        {
            _userContext = userContext;
            _cartRepository = cartRepository;
        }

        public async Task Handle(ClearCartCommand request, CancellationToken ct)
        {
            var userId = _userContext.User.UserId;
            await _cartRepository.DeleteCartAsync(userId, ct);
        }
    }
}
