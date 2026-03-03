using Catalog.Application.Common.Outbox;

namespace Catalog.Application.Abstractions
{
    public interface IOutboxRepository
    {
        Task AddAsync(OutboxMessage message, CancellationToken cancellationToken);

        Task<IReadOnlyCollection<OutboxMessage>> GetUnprocessedAsync(
            int batchSize,
            CancellationToken cancellationToken);

        Task MarkAsProcessedAsync(
            Guid messageId,
            DateTime processedOnUtc,
            CancellationToken cancellationToken);
    }
}
