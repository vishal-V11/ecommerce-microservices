using Shared.Messaging.Contracts;
using Shared.Messaging.Enums;

namespace Shared.Messaging.Events.Order
{
    public sealed record OrderCreatedEvent(
    Guid CorrelationId,
    Guid OrderId,
    string UserId,
    decimal TotalAmount,
    PaymentMethod PaymentMethod,
    IReadOnlyList<OrderItemContract> Items,
    DateTime OccurredOn);
}
