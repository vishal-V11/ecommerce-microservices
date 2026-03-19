using Inventory.API.DTO;
using Inventory.API.Entities;

namespace Inventory.API.Interfaces
{
    public interface IInventoryService
    {
        Task<InventoryItem> GetByProductIdAsync(Guid productId, CancellationToken ct = default);
        Task AddStockAsync(Guid productId, int qty, CancellationToken ct = default);
        Task CreateInventoryItemAsync(Guid productId, CancellationToken ct = default);
        Task LockStockBatchAsync(IReadOnlyList<StockItemDto> items, CancellationToken ct = default);
        Task ConfirmStockBatchAsync(IReadOnlyList<StockItemDto> items, CancellationToken ct = default);
        Task ReleaseStockBatchAsync(IReadOnlyList<StockItemDto> items, CancellationToken ct = default);
    }
}
