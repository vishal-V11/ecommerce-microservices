using Inventory.API.Entities;

namespace Inventory.API.Interfaces
{
    public interface IInventoryService
    {
        Task<InventoryItem> GetByProductIdAsync(Guid productId, CancellationToken ct = default);
        Task AddStockAsync(Guid productId, int qty, CancellationToken ct = default);
        Task LockStockAsync(Guid productId, int qty, CancellationToken ct = default);
        Task ReleaseStockAsync(Guid productId, int qty, CancellationToken ct = default);
        Task ConfirmStockAsync(Guid productId, int qty, CancellationToken ct = default);
        Task CreateInventoryItemAsync(Guid productId, CancellationToken ct = default);
    }
}
