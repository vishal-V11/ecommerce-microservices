namespace Shared.Messaging.Events.Cart
{
    public sealed record CartClearEvent(
      Guid CorrelationId,
      string UserId,
      DateTime OccurredOn);
}
