using Catalog.Application.Abstractions;
using Catalog.Application.Common.Outbox;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Catalog.Infrastructure.Persistence.Mongo.Repositories
{
    public class OutboxRepository : IOutboxRepository
    {
        public Task AddAsync(OutboxMessage message, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<IReadOnlyCollection<OutboxMessage>> GetUnprocessedAsync(int batchSize, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task MarkAsProcessedAsync(Guid messageId, DateTime processedOnUtc, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }
    }
}
