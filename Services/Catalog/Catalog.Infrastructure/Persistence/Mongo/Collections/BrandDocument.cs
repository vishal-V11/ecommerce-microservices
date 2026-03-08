using MongoDB.Bson.Serialization.Attributes;

namespace Catalog.Infrastructure.Persistence.Mongo.Collections
{
    public class BrandDocument:BaseDocument
    {
        public string Name { get; set; }
    }
}
