using Catalog.Application.Abstractions;
using Catalog.Domain.Entities;
using Catalog.Infrastructure.Persistence.Mappings;
using Catalog.Infrastructure.Persistence.Mongo;
using Catalog.Infrastructure.Persistence.Mongo.Collections;
using MongoDB.Driver;

namespace Catalog.Infrastructure.Persistence.Repositories
{
    public sealed class ProductRepository : IProductRepository
    {

        private readonly MongoContext _context;
        private readonly MongoSessionAccessor _sessionAccessor;
        public ProductRepository(MongoSessionAccessor sessionAccessor, MongoContext context)
        {
            _context = context;
            _sessionAccessor = sessionAccessor;
        }
        public async Task<Product?> GetByIdAsync(Guid id, CancellationToken ct)
        {
            var doc = await _context.Products
                .Find(x => x.Id == id && !x.IsDeleted)
                .FirstOrDefaultAsync(ct);

            return doc is null ? null : ProductMapper.ToDomain(doc);
        }

        public async Task InsertAsync(Product product, CancellationToken ct)
        {
            var document = ProductMapper.ToDocument(product);

            if (_sessionAccessor.Session != null)
            {
                await _context.Products.InsertOneAsync(
                    _sessionAccessor.Session,
                    document,
                    cancellationToken: ct);
            }
            else
            {
                await _context.Products.InsertOneAsync(document, cancellationToken: ct);
            }
        }

        public async Task UpdateAsync(Product product, CancellationToken ct)
        {

            var update = Builders<ProductDocument>.Update
                .Set(x => x.Name, product.Name)
                .Set(x => x.Description, product.Description)
                .Set(x => x.Price, product.Price)
                .Set(x => x.Brand, new BrandSnapshot { Id = product.Brand.Id, Name = product.Brand.Name })
                .Set(x => x.Category, new CategorySnapshot { Id = product.Category.Id, Name = product.Category.Name })
                .Set(x=>x.ImageUrl, product.ImageUrl);

            var filter = Builders<ProductDocument>.Filter.Eq(x => x.Id, product.Id);

            if (_sessionAccessor.Session != null)
            {
                await _context.Products.UpdateOneAsync(
                    _sessionAccessor.Session
                    ,filter
                    ,update
                    ,cancellationToken: ct);
            }
            else
            {
                await _context.Products.UpdateOneAsync(
                    filter
                    , update
                    , cancellationToken: ct);
            }
        }

        public async Task DeleteAsync(Guid id, CancellationToken ct)
        {
            var update = Builders<ProductDocument>.Update
            .Set(x => x.IsDeleted, true)
            .Set(x => x.UpdatedAt, DateTimeOffset.UtcNow);

            if (_sessionAccessor.Session != null)
            {
                await _context.Products.UpdateOneAsync(
                    _sessionAccessor.Session,
                    x => x.Id == id,
                    update,
                    cancellationToken: ct);
            }
            else
            {
                await _context.Products.UpdateOneAsync(
                    x => x.Id == id,
                    update,
                    cancellationToken: ct);
            }
        }

        public async Task SetActiveAsync(Guid productId, bool isActive, CancellationToken ct)
        {
            var update = Builders<ProductDocument>.Update
            .Set(x => x.IsActive, true)
            .Set(x => x.UpdatedAt, DateTimeOffset.UtcNow);

            if (_sessionAccessor.Session != null)
            {
                await _context.Products.UpdateOneAsync(
                    _sessionAccessor.Session,
                    x => x.Id == productId,
                    update,
                    cancellationToken: ct);
            }
            else
            {
                await _context.Products.UpdateOneAsync(
                   x => x.Id == productId,
                   update,
                   cancellationToken: ct);

            }
        }
    }
}
