using Catalog.Domain.Entities;
using Catalog.Infrastructure.Persistence.Mongo.Collections;

namespace Catalog.Infrastructure.Persistence.Mappings
{
    public static class CategoryMapper
    {
        public static Category ToDomain(CategoryDocument doc)
        {
            return new Category(doc.Id, doc.Name);
        }

        public static CategoryDocument ToDocument(Category category)
        {
            return new CategoryDocument
            {
                Id = category.Id,
                Name = category.Name
            };
        }
    }
}
