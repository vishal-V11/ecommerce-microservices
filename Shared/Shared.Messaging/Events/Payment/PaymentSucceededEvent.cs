namespace Shared.Messaging.Events.Payment
{

    public sealed record PaymentSucceededEvent(
        Guid CorrelationId,  // OrderId
        string UserId,
        DateTimeOffset OccurredOn);
}
