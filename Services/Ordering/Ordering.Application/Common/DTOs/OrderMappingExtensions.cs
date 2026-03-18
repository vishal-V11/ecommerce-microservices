using Ordering.Domain.Entities;

namespace Ordering.Application.Common.DTOs
{
    internal static class OrderMappingExtensions
    {
        internal static OrderDto ToDto(this Order order)
        {
            return new OrderDto(
                order.OrderId,
                order.UserId,
                order.Status,
                order.PaymentMethod,
            new DeliveryAddressDto(
                order.DeliveryAddress.FullName,
                order.DeliveryAddress.AddressLine1,
                order.DeliveryAddress.AddressLine2,
                order.DeliveryAddress.City,
                order.DeliveryAddress.State,
                order.DeliveryAddress.Pincode,
                order.DeliveryAddress.PhoneNumber),
                order.Items.Select(i => new OrderItemDto(
                i.OrderItemId,
                i.ProductId,
                i.ProductName,
                i.UnitPrice,
                i.Quantity,
                i.TotalPrice)).ToList(),
            order.TotalAmount,
            order.CreatedAt);
            }
    }
}
