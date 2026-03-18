using Shared.Messaging.Contracts;

namespace Shared.Messaging.Events.Stock
{
    /// <summary>
    /// Published by the Saga when an order is created.
    /// Instructs the Inventory Service to reserve stock for the given items
    /// by incrementing ReservedQty. Stock is held but not yet deducted.
    /// </summary>
    public sealed record StockLockRequestedEvent(
        Guid CorrelationId,  // OrderId
        IReadOnlyList<OrderItemContract> Items,
        string UserId,
        DateTimeOffset OccurredOn);
}
