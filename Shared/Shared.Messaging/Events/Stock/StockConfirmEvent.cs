using Shared.Messaging.Contracts;

namespace Shared.Messaging.Events.Stock
{
    /// <summary>
    /// Published by the Saga after payment succeeds.
    /// Instructs the Inventory Service to convert the reservation into
    /// an actual deduction — decrements both ReservedQty and actual Qty.
    /// </summary>
    public sealed record StockConfirmEvent(
        Guid CorrelationId,  // OrderId
        IReadOnlyList<OrderItemContract> Items,
        DateTimeOffset OccurredOn);
}
