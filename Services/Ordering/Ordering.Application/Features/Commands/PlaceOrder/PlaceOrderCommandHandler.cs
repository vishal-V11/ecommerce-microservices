using MediatR;
using Ordering.Application.Abstractions;
using Ordering.Application.Common.DTOs;
using Ordering.Domain.Entities;
using Ordering.Domain.ValueObjects;
using Shared.Messaging.Contracts;
using Shared.Messaging.Enums;
using Shared.Messaging.Events.Order;

namespace Ordering.Application.Features.Commands.PlaceOrder
{
    public class PlaceOrderCommandHandler : IRequestHandler<PlaceOrderCommand, OrderDto>
    {
        private readonly IOrderRepository _orderRepository;
        private readonly IUserContext _userContext;
        private readonly IEventPublisher _eventPublisher;
        public PlaceOrderCommandHandler(IOrderRepository orderRepository,IUserContext userContext,IEventPublisher eventPublisher)
        {
            _orderRepository = orderRepository;
            _userContext = userContext;
            _eventPublisher = eventPublisher;
        }

        public async Task<OrderDto> Handle(PlaceOrderCommand command, CancellationToken ct)
        {
            var deliveryAddress = new DeliveryAddress(
            command.DeliveryAddress.FullName,
            command.DeliveryAddress.AddressLine1,
            command.DeliveryAddress.AddressLine2,
            command.DeliveryAddress.City,
            command.DeliveryAddress.State,
            command.DeliveryAddress.Pincode,
            command.DeliveryAddress.PhoneNumber);

            var order = Order.Create(
            _userContext.User.UserId,
            command.PaymentMethod,
            deliveryAddress,
            command.Items.Select(i => (i.ProductId, i.ProductName, i.UnitPrice, i.Quantity)));

            await _orderRepository.AddAsync(order, ct);

            //ToDo add outbox pattern later so our event and save can be atomic
            await _eventPublisher.PublishAsync(new OrderCreatedEvent(
                CorrelationId: order.OrderId,
                OrderId: order.OrderId,
                UserId: order.UserId,
                TotalAmount: order.TotalAmount,
                PaymentMethod: (PaymentMethod)order.PaymentMethod,  // map Domain enum → Shared.Messaging enum
                Items: order.Items.Select(i => new OrderItemContract(i.ProductId, i.Quantity)).ToList(),
                OccurredOn: DateTime.UtcNow), ct);

            await _orderRepository.SaveChangesAsync(ct);
            return order.ToDto();
        }
    }
}
