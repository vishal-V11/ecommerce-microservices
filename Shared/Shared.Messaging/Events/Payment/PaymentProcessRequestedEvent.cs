using Shared.Messaging.Enums;

namespace Shared.Messaging.Events.Payment
{
    public sealed record PaymentProcessRequestedEvent(
      Guid CorrelationId,  // OrderId
      string UserId,
      decimal Amount,
      PaymentMethod PaymentMethod,
      DateTimeOffset OccurredOn);
}
