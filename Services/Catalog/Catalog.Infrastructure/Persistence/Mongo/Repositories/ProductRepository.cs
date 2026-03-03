using Catalog.Application.Abstractions;
using Catalog.Domain.Entities;

namespace Catalog.Infrastructure.Persistence.Mongo.Repositories
{
    public class ProductRepository : IProductRepository
    {
        public Task AddAsync(Product product)
        {
            throw new NotImplementedException();
        }

        public Task DeleteAsync(Guid productId)
        {
            throw new NotImplementedException();
        }

        public Task<Product> GetByProductIdAsync(Guid publicId)
        {
            throw new NotImplementedException();
        }

        public Task<List<Product>> GetPagedAsync(int page, int pageSize)
        {
            throw new NotImplementedException();
        }

        public Task UpdateAsync(Product product)
        {
            throw new NotImplementedException();
        }
    }
}
