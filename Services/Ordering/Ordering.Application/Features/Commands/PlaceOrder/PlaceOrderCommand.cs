using MediatR;
using Ordering.Application.Common.DTOs;
using Ordering.Domain.Enums;

namespace Ordering.Application.Features.Commands.PlaceOrder
{
    public sealed record PlaceOrderCommand(
    PaymentMethod PaymentMethod,
    DeliveryAddressRequest DeliveryAddress,
    IReadOnlyList<OrderItemRequest> Items) : IRequest<OrderDto>;

    public sealed record DeliveryAddressRequest(
        string FullName,
        string AddressLine1,
        string? AddressLine2,
        string City,
        string State,
        string Pincode,
        string PhoneNumber);

    public sealed record OrderItemRequest(
        Guid ProductId,
        string ProductName,
        decimal UnitPrice,
        int Quantity);
}
