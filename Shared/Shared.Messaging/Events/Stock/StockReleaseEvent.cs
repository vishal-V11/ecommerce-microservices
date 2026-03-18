using Shared.Messaging.Contracts;

namespace Shared.Messaging.Events.Stock
{
    /// <summary>
    /// Published by the Saga after payment fails.
    /// Instructs the Inventory Service to release the reservation —
    /// decrements ReservedQty only. Actual stock quantity remains untouched.
    /// </summary>
    public sealed record StockReleaseEvent(
        Guid CorrelationId,  // OrderId
        IReadOnlyList<OrderItemContract> Items,
        DateTime OccurredOn);
}
