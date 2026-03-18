using Ordering.Domain.Enums;

namespace Ordering.Application.Common.DTOs
{
    public sealed record OrderDto(
         Guid OrderId,
         string UserId,
         OrderStatus Status,
         PaymentMethod PaymentMethod,
         DeliveryAddressDto DeliveryAddress,
         IReadOnlyList<OrderItemDto> Items,
         decimal TotalAmount,
         DateTimeOffset CreatedAt);

    public sealed record DeliveryAddressDto(
        string FullName,
        string AddressLine1,
        string? AddressLine2,
        string City,
        string State,
        string Pincode,
        string PhoneNumber);

    public sealed record OrderItemDto(
        Guid OrderItemId,
        Guid ProductId,
        string ProductName,
        decimal UnitPrice,
        int Quantity,
        decimal TotalPrice);
}
