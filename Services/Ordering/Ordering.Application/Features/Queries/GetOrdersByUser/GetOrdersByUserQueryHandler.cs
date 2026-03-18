using MediatR;
using Ordering.Application.Abstractions;
using Ordering.Application.Common.DTOs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ordering.Application.Features.Queries.GetOrdersByUser
{
    public sealed class GetOrdersByUserQueryHandler : IRequestHandler<GetOrdersByUserQuery, IReadOnlyList<OrderDto>>
    {
        private readonly IOrderRepository _orderRepository;
        private readonly IUserContext _userContext;
        public GetOrdersByUserQueryHandler(IOrderRepository orderRepository,IUserContext userContext)
        {
            _orderRepository = orderRepository;
            _userContext = userContext;
        }

        public async Task<IReadOnlyList<OrderDto>> Handle(GetOrdersByUserQuery request, CancellationToken ct)
        {
            var orders = await _orderRepository.GetByUserIdAsync(_userContext.User.UserId, ct);
            return orders.Select(o => o.ToDto()).ToList();
        }
    }
}
