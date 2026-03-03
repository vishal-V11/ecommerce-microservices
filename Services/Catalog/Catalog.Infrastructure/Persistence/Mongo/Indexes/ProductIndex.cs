using Catalog.Infrastructure.Persistence.Mongo.Collections;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Catalog.Infrastructure.Persistence.Mongo.Indexes
{
    public sealed class ProductIndex : IMongoIndex
    {
        private readonly MongoContext _context;

        public ProductIndex(MongoContext context)
        {
            _context = context;
        }
        public async Task CreateAsync(CancellationToken cancellationToken = default)
        {
            var indexKeys = Builders<ProductDocument>
            .IndexKeys
            .Ascending(p => p.Name);

            var indexOptions = new CreateIndexOptions
            {
                Unique = true
            };

             var model = new CreateIndexModel<ProductDocument>(indexKeys,indexOptions);

            await _context.Products.Indexes.CreateOneAsync(model,cancellationToken:cancellationToken);
        }
    }
}
