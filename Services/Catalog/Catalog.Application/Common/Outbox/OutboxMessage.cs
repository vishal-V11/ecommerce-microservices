namespace Catalog.Application.Common.Outbox
{
    public sealed record OutboxMessage
    (
        Guid EventId
        , string Topic
        , string Payload
        , string CorrelationId
        ,DateTimeOffset OccurredOnUtc
    );
}
