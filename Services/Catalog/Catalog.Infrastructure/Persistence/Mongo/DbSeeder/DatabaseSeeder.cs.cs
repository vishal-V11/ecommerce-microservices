using Catalog.Infrastructure.Persistence.Mongo.Collections;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
                new BrandDocument { BrandId = Guid.NewGuid(), Name = "Apple" },
                new BrandDocument { BrandId = Guid.NewGuid(), Name = "Samsung" },
                new BrandDocument { BrandId = Guid.NewGuid(), Name = "Sony" }
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
            new CategoryDocument { CategoryId = Guid.NewGuid(), Name = "Mobiles" },
            new CategoryDocument { CategoryId = Guid.NewGuid(), Name = "Electronics" },
            new CategoryDocument { CategoryId = Guid.NewGuid(), Name = "Accessories" }
        };

            await _context.Categories.InsertManyAsync(categories);
        }

        

    }
}
