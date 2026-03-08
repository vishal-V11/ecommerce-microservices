using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Catalog.Infrastructure.Persistence.Mongo.Collections
{
    public class ProductDocument:BaseDocument
    {
        public required string Name { get; set; }
        public string Description { get; set; }
        public required BrandSnapshot Brand {  get; set; }
        public required CategorySnapshot Category { get; set; }

        [BsonRepresentation(BsonType.Decimal128)]
        public decimal Price { get; set; }
        public string ImageUrl { get; set; } 
        public bool IsActive { get; set; }

    }

    public sealed class ProductImageDocument
    {
        public Guid Id { get;set;  }
        public string Url { get; set; } = default!;
        public int SortOrder { get; set; }
    }

    public sealed class BrandSnapshot
    {
        public Guid Id { get; set; }
        public required string Name { get; set; }
    }

    public sealed class CategorySnapshot
    {
        public Guid Id { get; set; }
        public required string Name { get; set; }
    }
}
