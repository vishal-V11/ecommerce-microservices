namespace Shared.Messaging.Events.Stock
{
    /// <summary>
    /// Published by the Inventory Service when stock has been successfully reserved
    /// for all items in the order. Signals the Saga to proceed with payment.
    /// </summary>
    public sealed record StockLockedEvent(
        Guid CorrelationId,  // OrderId
        DateTimeOffset OccurredOn);
}
