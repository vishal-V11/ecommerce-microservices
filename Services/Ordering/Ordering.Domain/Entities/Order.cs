using Ordering.Domain.Enums;
using Ordering.Domain.Exceptions;
using Ordering.Domain.ValueObjects;

namespace Ordering.Domain.Entities
{
    public class Order
    {
        public Guid OrderId { get; }
        public string UserId { get; }
        public OrderStatus Status { get; private set; }
        public PaymentMethod PaymentMethod { get; }
        public DeliveryAddress DeliveryAddress { get; }
        public decimal TotalAmount => _items.Sum(x => x.TotalPrice);
        public DateTimeOffset CreatedAt { get; }

        private readonly List<OrderItem> _items = [];
        public IReadOnlyList<OrderItem> Items => _items.AsReadOnly();

        private Order(string userId, PaymentMethod paymentMethod, DeliveryAddress deliveryAddress)
        {
            OrderId = Guid.NewGuid();
            UserId = userId;
            Status = OrderStatus.Pending;
            PaymentMethod = paymentMethod;
            DeliveryAddress = deliveryAddress;
            CreatedAt = DateTimeOffset.UtcNow;
        }


        public static Order Create(
            string userId,
            PaymentMethod paymentMethod,
            DeliveryAddress deliveryAddress,
            IEnumerable<(Guid ProductId,string ProductName, decimal UnitPrice, int Quantity)> items
            )
        {
            var order = new Order(userId, paymentMethod, deliveryAddress);

            foreach (var item in items)
            {
                order._items.Add(new OrderItem(order.OrderId,item.ProductId,item.ProductName,item.UnitPrice,item.Quantity));
            }

            return order;
        }

        public void ConfirmStatus()
        {
            if (Status != OrderStatus.Pending)
                throw new InvalidOrderStatusTransitionException(OrderId, Status, OrderStatus.Confirmed);

            Status = OrderStatus.Confirmed;
        }

        public void CancelStatus()
        {
            if (Status is OrderStatus.Shipped or OrderStatus.Delivered)
                throw new InvalidOrderStatusTransitionException(OrderId, Status, OrderStatus.Cancelled);

            Status = OrderStatus.Cancelled;
        }

        public void MarkShipped()
        {
            if (Status != OrderStatus.Confirmed)
                throw new InvalidOrderStatusTransitionException(OrderId, Status, OrderStatus.Shipped);

            Status = OrderStatus.Shipped;
        }

        public void MarkDelivered()
        {
            if (Status != OrderStatus.Shipped)
                throw new InvalidOrderStatusTransitionException(OrderId, Status, OrderStatus.Delivered);

            Status = OrderStatus.Delivered;
        }

        //Empty constructore for EF
        private Order(){}

    }
}
