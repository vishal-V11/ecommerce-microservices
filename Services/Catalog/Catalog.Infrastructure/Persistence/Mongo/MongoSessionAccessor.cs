using MongoDB.Driver;

namespace Catalog.Infrastructure.Persistence.Mongo
{
    public class MongoSessionAccessor
    {
        public IClientSessionHandle? Session { get;set;  }
    }
}
