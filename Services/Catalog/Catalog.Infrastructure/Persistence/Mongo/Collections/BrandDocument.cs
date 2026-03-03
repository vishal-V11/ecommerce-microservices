using MongoDB.Bson.Serialization.Attributes;

namespace Catalog.Infrastructure.Persistence.Mongo.Collections
{
    public class BrandDocument:BaseDocument
    {
        [BsonElement("BrandId")]
        public Guid BrandId { get; set; }
        [BsonElement("Name")]
        public string Name { get; set; }
    }
}
