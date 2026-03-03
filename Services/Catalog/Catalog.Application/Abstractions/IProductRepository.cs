using Catalog.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Catalog.Application.Abstractions
{
    public interface IProductRepository
    {
        Task<Product> GetByProductIdAsync(Guid productId);
        Task<List<Product>> GetPagedAsync(int page, int pageSize);
        Task AddAsync(Product product);
        Task UpdateAsync(Product product);
        Task DeleteAsync(Guid productId);
    }
}
