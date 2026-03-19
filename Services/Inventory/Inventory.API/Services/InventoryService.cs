using Inventory.API.DTO;
using Inventory.API.Entities;
using Inventory.API.Exceptions;
using Inventory.API.Interfaces;
using Microsoft.EntityFrameworkCore;
using Polly;
using Polly.Registry;

namespace Inventory.API.Services
{
    public class InventoryService : IInventoryService
    {
        private readonly IInventoryRepository _repository;
        private readonly ResiliencePipeline _pipeline;
        private readonly ILogger<InventoryService> _logger;
        public InventoryService(IInventoryRepository repository
            , ResiliencePipelineProvider<string> pipelineProvider
            , ILogger<InventoryService> logger)
        {
            _repository = repository;
            _pipeline = pipelineProvider.GetPipeline("inventory-stock");
            _logger = logger;

        }
        public async Task<InventoryItem> GetByProductIdAsync(Guid productId, CancellationToken ct = default)
        {
            var item = await _repository.GetByProductIdAsync(productId, ct);
            if (item is null)
                throw new InventoryItemNotFoundException(productId);

            return item;
        }

        public async Task AddStockAsync(Guid productId, int qty, CancellationToken ct = default)
        {
            var item = await GetByProductIdAsync(productId, ct);
            item.AddStock(qty);
            await _repository.UpdateAsync(item, ct);
            _logger.LogInformation("Added {Qty} units to ProductId {ProductId}.", qty, productId);
        }

        public async Task CreateInventoryItemAsync(Guid productId, CancellationToken ct = default)
        {
            var existing = await _repository.GetByProductIdAsync(productId, ct);
            if (existing is not null)
            {
                _logger.LogWarning("Inventory item for ProductId {ProductId} already exists. Skipping.", productId);
                return;
            }

            var item = InventoryItem.Create(productId);
            await _repository.AddAsync(item, ct);
            _logger.LogInformation("Inventory item created for ProductId {ProductId}.", productId);
        }


        public async Task LockStockBatchAsync(IReadOnlyList<StockItemDto> items, CancellationToken ct = default)
        {
            await ExecuteBatchWithRetryAsync(items, "lock", (item, orderItem) => item.LockStock(orderItem.Quantity), ct);
        }

        public async Task ConfirmStockBatchAsync(IReadOnlyList<StockItemDto> items, CancellationToken ct = default)
        {
            await ExecuteBatchWithRetryAsync(items, "confirm", (item, orderItem) => item.ConfirmStock(orderItem.Quantity), ct);
        }

        public async Task ReleaseStockBatchAsync(IReadOnlyList<StockItemDto> items, CancellationToken ct = default)
        {
            await ExecuteBatchWithRetryAsync(items, "release", (item, orderItem) => item.ReleaseStock(orderItem.Quantity), ct);
        }

        // --- Private ---
        private async Task ExecuteBatchWithRetryAsync(
            IReadOnlyList<StockItemDto> items,
            string operation,
            Action<InventoryItem, StockItemDto> action,
            CancellationToken ct)
        {
            try
            {
                await _pipeline.ExecuteAsync(async token =>
                {
                    var inventoryItems = await _repository.GetByIdAsync(
                        items.Select(i => i.ProductId).ToList(), token);

                    foreach (var orderItem in items)
                    {
                        var inventoryItem = inventoryItems.FirstOrDefault(i => i.ProductId == orderItem.ProductId)
                            ?? throw new InventoryItemNotFoundException(orderItem.ProductId);

                        action(inventoryItem, orderItem);
                    }

                    await _repository.SaveChangesAsync(token);
                }, ct);
            }
            catch (DbUpdateConcurrencyException ex)
            {
                _logger.LogError(ex, "Failed to {Operation} stock batch after all retry attempts.", operation);
                throw;
            }
        }

    }
}
