using Catalog.Domain.Entities;
using Catalog.Infrastructure.Persistence.Mongo.Collections;

namespace Catalog.Infrastructure.Persistence.Mappings
{
    public static class BrandMapper
    {
        public static Brand ToDomain(BrandDocument doc)
        {
            return new Brand(doc.Id, doc.Name);
        }

        public static BrandDocument ToDocument(Brand brand)
        {
            return new BrandDocument
            {
                Id = brand.Id,
                Name = brand.Name
            };
        }
    }
}
