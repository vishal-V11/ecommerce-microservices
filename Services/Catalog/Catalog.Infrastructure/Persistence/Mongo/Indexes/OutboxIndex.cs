using Catalog.Infrastructure.Persistence.Mongo.Collections;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Catalog.Infrastructure.Persistence.Mongo.Indexes
{
    public class OutboxIndex : IMongoIndex
    {
        private readonly MongoContext _context;
        public OutboxIndex(MongoContext context)
        {
            _context = context;
        }

        public async Task CreateAsync(CancellationToken cancellationToken = default)
        {
            var keys = Builders<OutboxMessageDocument>
            .IndexKeys
            .Ascending(x => x.Status)   
            .Ascending(x => x.NextRetryAtUtc)
            .Ascending(x => x.OccurredOnUtc);

            var model = new CreateIndexModel<OutboxMessageDocument>(keys);

            await _context.Outbox.Indexes.CreateOneAsync(model, cancellationToken: cancellationToken);

            var eventIdIndex = new CreateIndexModel<OutboxMessageDocument>(
            Builders<OutboxMessageDocument>.IndexKeys.Ascending(x => x.EventId),
            new CreateIndexOptions { Unique = true });

            await _context.Outbox.Indexes.CreateOneAsync(eventIdIndex,cancellationToken:cancellationToken);
        }
    }
}
