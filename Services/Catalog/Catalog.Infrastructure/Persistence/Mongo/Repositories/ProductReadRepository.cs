using Catalog.Application.Abstractions;
using Catalog.Application.Common.DTO;
using Catalog.Application.Common.Responses;
using Catalog.Application.Features.Products.Queries.SearchProducts;
using Catalog.Infrastructure.Persistence.Mongo.Collections;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Catalog.Infrastructure.Persistence.Mongo.Repositories
{
    public sealed class ProductReadRepository : IProductReadRepository
    {
        private readonly MongoContext _context;
        public ProductReadRepository(MongoContext context)
        {
            _context = context;
        }

        public async Task<ProductDetailDto?> GetByIdAsync(Guid id, CancellationToken ct)
        {
            var filter = Builders<ProductDocument>.Filter.And(
                Builders<ProductDocument>.Filter.Eq(x=>x.Id,id),
                Builders<ProductDocument>.Filter.Eq(x=>x.IsDeleted,false)                
            );

            return await _context.Products.Find(filter).Project(x => new ProductDetailDto
            { 
                ProductId = x.Id,
                Name = x.Name,
                Price = x.Price,
                Description = x.Description,
                ImageUrl = x.ImageUrl,
                Category = new CategoryDto { Id = x.Category.Id,Name = x.Category.Name},
                Brand = new BrandDto { Id = x.Brand.Id, Name = x.Brand.Name},
            })
            .FirstOrDefaultAsync(ct);
        }

        public async Task<PagedResult<ProductListVm>> GetPagedAsync(GetProductListQuery request, CancellationToken ct)
        {
            var builder = Builders<ProductDocument>.Filter;
            var filters = new List<FilterDefinition<ProductDocument>>
            {
                Builders<ProductDocument>.Filter.Eq(p => p.IsDeleted, false)
            };

            if (!string.IsNullOrEmpty(request.ProductName))
                if (!string.IsNullOrWhiteSpace(request.ProductName))
                {
                    filters.Add(builder.Regex(
                        x => x.Name,
                        new BsonRegularExpression(request.ProductName, "i")));
                }

            if (request.BrandId is not null)
                filters.Add(builder.Eq(x => x.Brand.Id, request.BrandId));
            

            if (request.CategoryId is not null)
                filters.Add(builder.Eq(x => x.Category.Id, request.CategoryId));

            if (request.IsActive is not null)
                filters.Add(builder.Eq(x => x.IsActive, request.IsActive));


            var combined = builder.And(filters);
            var sort = Builders<ProductDocument>.Sort.Descending(p => p.CreatedAt);

            var total = await _context.Products.CountDocumentsAsync(combined);

            var items = await _context.Products
                .Find(combined)
                .Sort(sort)
                .Skip((request.PageNumber - 1 ) * request.PageSize)
                .Limit(request.PageSize)
                .Project(x=> new ProductListVm
                {
                    ProductId = x.Id,
                    Name = x.Name,
                    Price = x.Price,
                    BrandName = x.Brand.Name,
                    CategoryName = x.Category.Name,
                    IsActive = x.IsActive
                }).ToListAsync(ct);


            return new PagedResult<ProductListVm>
            {
                Items = items,
                TotalCount = (int)total,
                Page = request.PageNumber,
                PageSize = request.PageSize
            };
        }

        
        public async Task<List<ProductSearchVm>> SearchAsync(SearchProductsQuery query,CursorDto? cursor,CancellationToken ct)
        {
            var filters = new List<FilterDefinition<ProductDocument>>
            {
                Builders<ProductDocument>.Filter.Eq(p => p.IsDeleted, false),
                Builders<ProductDocument>.Filter.Eq(p => p.IsActive,  true)
            };

            // Keyset — CreatedAt + ProductId tiebreaker
            if (cursor is not null)
            {
                filters.Add(
                    Builders<ProductDocument>.Filter.Or(
                        Builders<ProductDocument>.Filter.Lt(p => p.CreatedAt, cursor.CreatedAt),
                        Builders<ProductDocument>.Filter.And(
                            Builders<ProductDocument>.Filter.Eq(p => p.CreatedAt, cursor.CreatedAt),
                            Builders<ProductDocument>.Filter.Lt(p => p.Id, cursor.ProductId)
                        )
                    )
                );
            }

            if (!string.IsNullOrWhiteSpace(query.Search))
                filters.Add(Builders<ProductDocument>.Filter.Text(query.Search));

            if (query.CategoryId.HasValue)
                filters.Add(Builders<ProductDocument>.Filter.Eq(p => p.Category.Id, query.CategoryId.Value));

            if (query.BrandId.HasValue)
                filters.Add(Builders<ProductDocument>.Filter.Eq(p => p.Brand.Id, query.BrandId.Value));

            if (query.MinPrice.HasValue)
                filters.Add(Builders<ProductDocument>.Filter.Gte(p => p.Price, query.MinPrice.Value));

            if (query.MaxPrice.HasValue)
                filters.Add(Builders<ProductDocument>.Filter.Lte(p => p.Price, query.MaxPrice.Value));

            var combined = Builders<ProductDocument>.Filter.And(filters);

            // Sort must match cursor fields
            var sort = Builders<ProductDocument>.Sort
                .Descending(p => p.CreatedAt)
                .Descending(p => p.Id);

            return await _context.Products
                .Find(combined)
                .Sort(sort)
                .Limit(query.PageSize + 1)  // +1 handled in handler
                .Project(p => new ProductSearchVm
                {
                    ProductId = p.Id,
                    Name = p.Name,
                    Price = p.Price,
                    ImageUrl = p.ImageUrl,
                    BrandName = p.Brand.Name,
                    CreatedAt = p.CreatedAt.UtcDateTime
                })
                .ToListAsync(ct);
        }

    }
}
