using Catalog.Application.Abstractions;
using Catalog.Domain.Entities;
using Catalog.Infrastructure.Persistence.Mongo;
using MongoDB.Driver;

namespace Catalog.Infrastructure.Persistence.Repositories
{
    public sealed class CategoryRepository : ICategoryRepository
    {
        private readonly MongoContext _context;

        public CategoryRepository(MongoContext context)
        {
            _context = context;
        }

        public async Task<Category?> GetByIdAsync(Guid id, CancellationToken ct)
        {
            var doc = await _context.Categories
               .Find(x => x.Id == id && !x.IsDeleted)
               .FirstOrDefaultAsync(ct);

            if (doc is null)
                return null;

            return new Category(doc.Id, doc.Name);
        }
    }
}
