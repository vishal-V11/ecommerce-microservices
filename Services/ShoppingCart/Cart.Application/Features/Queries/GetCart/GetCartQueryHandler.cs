using Cart.Application.Abstractions;
using Cart.Application.Common.DTOs;
using Cart.Application.Extensions;
using MediatR;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cart.Application.Features.Queries.GetCart
{
    public sealed class GetCartQueryHandler : IRequestHandler<GetCartQuery, CartDto?>
    {
        private readonly IUserContext _userContext;
        private readonly ICartRepository _cartRepository;
        public GetCartQueryHandler(IUserContext userContext, ICartRepository cartRepository)
        {
            _userContext = userContext;
            _cartRepository = cartRepository;
        }
        public async Task<CartDto?> Handle(GetCartQuery request, CancellationToken ct)
        {
            var userId = _userContext.User.UserId;

            var cart = await _cartRepository.GetCartAsync(userId, ct);

            return cart?.ToDto();
        }
    }
}
