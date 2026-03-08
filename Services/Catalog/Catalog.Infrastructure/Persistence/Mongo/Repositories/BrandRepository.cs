using Catalog.Application.Abstractions;
using Catalog.Domain.Entities;
using Catalog.Infrastructure.Persistence.Mongo;
using MongoDB.Driver;

namespace Catalog.Infrastructure.Persistence.Repositories
{
    public sealed class BrandRepository : IBrandRepository
    {
        private readonly MongoContext _context;
        public BrandRepository(MongoContext context)
        {
            _context = context;
        }

        public async Task<Brand?> GetByIdAsync(Guid id, CancellationToken ct)
        {
            var doc = await _context.Brands
              .Find(x => x.Id == id && !x.IsDeleted)
              .FirstOrDefaultAsync(ct);

            if (doc is null)
                return null;

            return new Brand(doc.Id, doc.Name);
        }
    }
}
