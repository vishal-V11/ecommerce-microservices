using MediatR;
using Ordering.Application.Abstractions;
using Ordering.Application.Common.DTOs;
using Ordering.Domain.Exceptions;
using static Microsoft.EntityFrameworkCore.DbLoggerCategory;

namespace Ordering.Application.Features.Queries.GetOrderById
{
    public sealed class GetOrderByIdQueryHandler : IRequestHandler<GetOrderByIdQuery, OrderDto>
    {
        private readonly IOrderRepository _orderRepository;
        public GetOrderByIdQueryHandler(IOrderRepository orderRepository)
        {
            _orderRepository = orderRepository;
        }
        public async Task<OrderDto> Handle(GetOrderByIdQuery query, CancellationToken ct)
        {
            var order = await _orderRepository.GetByIdAsync(query.OrderId, ct)
            ?? throw new OrderNotFoundException(query.OrderId);

            return order.ToDto();
        }
    }
}
