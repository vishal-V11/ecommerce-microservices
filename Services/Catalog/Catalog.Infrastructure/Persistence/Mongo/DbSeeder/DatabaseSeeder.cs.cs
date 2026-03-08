using Catalog.Infrastructure.Persistence.Mongo.Collections;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace Catalog.Infrastructure.Persistence.Mongo.DbSeeder
{
    public sealed class DatabaseSeeder
    {
        private readonly MongoContext _context;
        private readonly ILogger<DatabaseSeeder> _logger;

        public DatabaseSeeder(MongoContext context, ILogger<DatabaseSeeder> logger)
        {
            _context = context;
            _logger = logger;   
        }

        public async Task SeedAsync()
        {
            await SeedBrandAsync();
            await SeedCategoryAsync();
        }

        private async Task SeedBrandAsync()
        {
            var count = await _context.Brands.CountDocumentsAsync(FilterDefinition<BrandDocument>.Empty);

            if (count > 0)
                return;

            _logger.LogInformation("Seeding default brands...");

            var brands = new[]
            {
                new BrandDocument { Id = Guid.NewGuid(), Name = "Apple",IsDeleted = false },
                new BrandDocument { Id = Guid.NewGuid(), Name = "Samsung",IsDeleted = false },
                new BrandDocument { Id = Guid.NewGuid(), Name = "Sony" ,IsDeleted = false}
            };

            await _context.Brands.InsertManyAsync(brands);
        }
        
        private async Task SeedCategoryAsync()
        {
            var count = await _context.Categories.CountDocumentsAsync(FilterDefinition<CategoryDocument>.Empty);

            if (count > 0)
                return;

            _logger.LogInformation("Seeding default categories...");

            var categories = new[]
            {
            new CategoryDocument { Id = Guid.NewGuid(), Name = "Mobiles",IsDeleted = false },
            new CategoryDocument { Id = Guid.NewGuid(), Name = "Electronics",IsDeleted = false },
            new CategoryDocument { Id = Guid.NewGuid(), Name = "Accessories",IsDeleted = false }
        };

            await _context.Categories.InsertManyAsync(categories);
        }

        

    }
}
