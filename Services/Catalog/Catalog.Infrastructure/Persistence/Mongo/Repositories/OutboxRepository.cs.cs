using Catalog.Application.Abstractions;
using Catalog.Application.Common.Outbox;
using Catalog.Infrastructure.Persistence.Mongo;
using Catalog.Infrastructure.Persistence.Mongo.Collections;
using MongoDB.Driver;

namespace Catalog.Infrastructure.Persistence.Repositories
{
    public class OutboxRepository : IOutboxRepository
    {
        private readonly MongoContext _context;
        public OutboxRepository(MongoContext context)
        {
            _context = context;
        }

        public async Task AddAsync(OutboxMessage message, CancellationToken ct)
        {
            var doc = new OutboxMessageDocument
            {
                EventId = message.EventId,
                Topic = message.Topic,
                Payload = message.Payload,
                CorrelationId = message.CorrelationId,
                OccurredOnUtc = message.OccurredOnUtc,
                Status = OutboxStatus.Pending,
                NextRetryAtUtc = DateTimeOffset.UtcNow
            };

            await _context.Outbox.InsertOneAsync(doc, cancellationToken: ct);
        }

        public async Task<IReadOnlyCollection<OutboxMessage>> GetUnprocessedAsync(
            int batchSize
            , CancellationToken ct)
        {
            var now = DateTimeOffset.UtcNow;

            var filter = Builders<OutboxMessageDocument>.Filter.And(
                Builders<OutboxMessageDocument>.Filter.Eq(x => x.Status, OutboxStatus.Pending),
                Builders<OutboxMessageDocument>.Filter.Lte(x => x.NextRetryAtUtc, now)
            );

            var documents = await _context.Outbox
            .Find(filter)
            .SortBy(x => x.OccurredOnUtc)
            .Limit(batchSize)
            .ToListAsync(ct);

            return documents.Select(d => new OutboxMessage(
                d.EventId,
                d.Topic,
                d.Payload,
                d.CorrelationId,
                d.OccurredOnUtc.UtcDateTime
            )).ToList();
        }

        public async Task MarkAsProcessedAsync(
            Guid messageId,
            DateTime processedOnUtc,
            CancellationToken ct
            )
        {
            var update = Builders<OutboxMessageDocument>.Update
                .Set(x => x.Status, OutboxStatus.Processed)
                .Set(x => x.ProcessedAtUtc, processedOnUtc);

            await _context.Outbox.UpdateOneAsync(
                x => x.EventId == messageId,
                update,
                cancellationToken: ct);
        }

        public async Task RecordFailureAsync(
            Guid eventId,
            string error,
            CancellationToken ct)
        {
            var doc = await _context.Outbox
                .Find(x => x.EventId == eventId)
                .FirstOrDefaultAsync(ct);

            if (doc is null)
                return;

            var retryCount = doc.RetryCount + 1;

            if (retryCount >= 3)
            {
                var update = Builders<OutboxMessageDocument>.Update
                    .Set(x => x.Status, OutboxStatus.Failed)
                    .Set(x => x.LastError, error)
                    .Push(x => x.ErrorHistory, new OutboxError
                    {
                        Attempt = retryCount,
                        Error = error,
                        OccurredAtUtc = DateTime.UtcNow
                    });

                await _context.Outbox.UpdateOneAsync(
                    x => x.EventId == eventId,
                    update,
                    cancellationToken: ct);

                return;
            }

            var delay = TimeSpan.FromMinutes(Math.Pow(2, retryCount));

            var updateRetry = Builders<OutboxMessageDocument>.Update
                .Set(x => x.RetryCount, retryCount)
                .Set(x => x.NextRetryAtUtc, DateTimeOffset.UtcNow.Add(delay))
                .Set(x => x.LastError, error)
                .Push(x => x.ErrorHistory, new OutboxError
                {
                    Attempt = retryCount,
                    Error = error,
                    OccurredAtUtc = DateTime.UtcNow
                });

            await _context.Outbox.UpdateOneAsync(
                x => x.EventId == eventId,
                updateRetry,
                cancellationToken: ct);
        }
    }
}
