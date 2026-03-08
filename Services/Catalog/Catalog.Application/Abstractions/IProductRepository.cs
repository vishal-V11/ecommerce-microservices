using Catalog.Domain.Entities;

namespace Catalog.Application.Abstractions
{
    public interface IProductRepository
    {
        Task<Product?> GetByIdAsync(Guid productId, CancellationToken ct);
        Task InsertAsync(Product product, CancellationToken ct);
        Task UpdateAsync(Product product, CancellationToken ct);
        Task SetActiveAsync(Guid productId,bool isActive, CancellationToken ct);
        Task DeleteAsync(Guid productId, CancellationToken ct);
    }
}
