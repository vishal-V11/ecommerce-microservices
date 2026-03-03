using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Catalog.Infrastructure.Persistence.Mongo.Collections
{
    public class ProductDocument:BaseDocument
    {
        public required string Name { get; set; }
        public string Description { get; set; }
        public required BrandDocument Brand {  get; set; }
        public required CategoryDocument Category { get; set; }

        [BsonRepresentation(BsonType.Decimal128)]
        public decimal Price { get; set; }
        public List<ProductImage> Images { get; set; } = new();

    }

    public sealed class ProductImage
    {
        public string Url { get; set; } = default!;
        public int SortOrder { get; set; }
    }
}
