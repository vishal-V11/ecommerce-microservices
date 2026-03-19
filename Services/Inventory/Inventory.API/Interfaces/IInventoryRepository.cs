using Inventory.API.Entities;

namespace Inventory.API.Interfaces
{
    public interface IInventoryRepository
    {
        Task<InventoryItem?> GetByProductIdAsync(Guid ProductId, CancellationToken ct);
        Task AddAsync(InventoryItem item,CancellationToken ct);
        Task UpdateAsync(InventoryItem item, CancellationToken ct);
        Task<List<InventoryItem>> GetByIdAsync(List<Guid> productids, CancellationToken ct = default);
        Task SaveChangesAsync(CancellationToken ct = default);
    }
}
