using Catalog.Domain.Entities;
using Catalog.Infrastructure.Persistence.Mongo.Collections;

namespace Catalog.Infrastructure.Persistence.Mappings
{
    public static class ProductMapper
    {
        public static ProductDocument ToDocument(Product product)
        {
            return new ProductDocument
            {
                Id = product.Id,
                Name = product.Name,
                Description = product.Description,
                Price = product.Price,
                ImageUrl = product.ImageUrl,

                Brand = new BrandSnapshot
                {
                    Id = product.Brand.Id,
                    Name = product.Brand.Name
                },

                Category = new CategorySnapshot
                {
                    Id = product.Category.Id,
                    Name = product.Category.Name
                },

               

                IsDeleted = product.IsActive,
                CreatedAt = product.CreatedAt,
                UpdatedAt = product.UpdatedAt
            };
        }

        public static Product ToDomain(ProductDocument doc)
        {
            var brand = new Brand(doc.Brand.Id, doc.Brand.Name);
            var category = new Category(doc.Category.Id, doc.Category.Name);

            var product = new Product(
                doc.Id,
                doc.Name,
                doc.Price,
                brand,
                category,
                doc.Description,
                doc.ImageUrl
            );

            return product;
        }
    }
}
