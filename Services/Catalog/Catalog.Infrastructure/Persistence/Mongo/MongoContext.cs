using Catalog.Infrastructure.Persistence.Mongo.Collections;
using Catalog.Infrastructure.Settings;
using Microsoft.Extensions.Options;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Catalog.Infrastructure.Persistence.Mongo
{
    public class MongoContext
    {
        public IMongoClient Client { get; }
        public IMongoDatabase Database { get; }

        public MongoContext(IOptions<MongoSettings> settings)
        {
            Client = new MongoClient(settings.Value.ConnectionString);
            Database = Client.GetDatabase(settings.Value.DatabaseName);
        }

        public IMongoCollection<ProductDocument> Products
            => Database.GetCollection<ProductDocument>("Products");
        public IMongoCollection<BrandDocument> Brands
            => Database.GetCollection<BrandDocument>("Brands");
        public IMongoCollection<CategoryDocument> Categories
            => Database.GetCollection<CategoryDocument>("Categories");
        public IMongoCollection<OutboxMessageDocument> Outbox
            => Database.GetCollection<OutboxMessageDocument>("Outbox");
    }
}
