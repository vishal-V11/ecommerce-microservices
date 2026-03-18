namespace Shared.Messaging.Events.Stock
{
    /// <summary>
    /// Published by the Inventory Service when stock reservation fails
    /// due to insufficient quantity for one or more items.
    /// Signals the Saga to cancel the order and notify the user.
    /// </summary>
    public sealed record StockLockFailedEvent(
        Guid CorrelationId,  // OrderId
        string Reason,
        DateTimeOffset OccurredOn);
}
