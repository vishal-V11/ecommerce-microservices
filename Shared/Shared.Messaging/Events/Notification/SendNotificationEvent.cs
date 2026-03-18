namespace Shared.Messaging.Events.Notification
{
    public sealed record SendNotificationEvent(
        Guid CorrelationId,  // OrderId
        string UserId,
        string Message,
        DateTimeOffset OccurredOn);
}
