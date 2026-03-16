using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Catalog.Infrastructure.Persistence.Mongo.Collections
{
    public class OutboxMessageDocument
    {
        [BsonId]
        public ObjectId Id { get; set; }

        public Guid EventId { get; set; }

        public string Topic { get; set; } = default!;

        public string Payload { get; set; } = default!;
        public string CorrelationId { get; init; } = default!;

        // Pending | Processed | Failed
        public string Status { get; set; } = OutboxStatus.Pending;

        public int RetryCount { get; set; } = 0;

        public DateTimeOffset OccurredOnUtc { get; set; }

        public DateTimeOffset? ProcessedAtUtc { get; set; }

        public DateTimeOffset? NextRetryAtUtc { get; set; }


        // Quick access for monitoring
        public string? LastError { get; set; }

        [BsonElement("errorHistory")]
        public List<OutboxError> ErrorHistory { get; set; } = new();
    }

    public class OutboxError
    {
        [BsonElement("attempt")]
        public int Attempt { get; set; }

        [BsonElement("error")]
        public string Error { get; set; } = default!;

        [BsonElement("occurredAt")]
        public DateTime OccurredAtUtc { get; set; }
    }
    public static class OutboxStatus
    {
        public const string Pending = "Pending";
        public const string Processed = "Processed";
        public const string Failed = "Failed";
    }
}
