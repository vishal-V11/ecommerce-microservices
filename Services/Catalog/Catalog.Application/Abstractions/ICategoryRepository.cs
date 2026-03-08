using Catalog.Domain.Entities;

namespace Catalog.Application.Abstractions
{
    public interface ICategoryRepository
    {
        Task<Category?> GetByIdAsync(Guid id, CancellationToken ct);
    }
}
