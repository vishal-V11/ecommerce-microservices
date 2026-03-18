namespace Shared.Messaging.Events.Payment
{
    public sealed record PaymentFailedEvent(
     Guid CorrelationId,  // OrderId
     string UserId,
     string Reason,
     DateTimeOffset OccurredOn);
}
