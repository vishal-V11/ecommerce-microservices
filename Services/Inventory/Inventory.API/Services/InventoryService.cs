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

        public async Task LockStockAsync(Guid productId, int qty, CancellationToken ct = default)
        {
            await ExecuteWithRetryAsync(productId, qty, "lock", async item =>
            {
                item.LockStock(qty);
                await _repository.UpdateAsync(item, ct);
            }, ct);
        }

        public async Task ReleaseStockAsync(Guid productId, int qty, CancellationToken ct = default)
        {
            await ExecuteWithRetryAsync(productId, qty, "release", async item =>
             {
                 item.ReleaseStock(qty);
                 await _repository.UpdateAsync(item, ct);
             }, ct);
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

        public async Task ConfirmStockAsync(Guid productId, int qty, CancellationToken ct = default)
        {
            await ExecuteWithRetryAsync(productId, qty, "confirm", async item =>
            {
                item.ConfirmStock(qty);
                await _repository.UpdateAsync(item, ct);
            }, ct);
        }

        // --- Private ---

        private async Task ExecuteWithRetryAsync(
            Guid productId,
            int qty,
            string operation,
            Func<InventoryItem, Task> action,
            CancellationToken ct)
        {
            try
            {
                await _pipeline.ExecuteAsync(async token =>
                {
                    var item = await _repository.GetByProductIdAsync(productId, token)
                        ?? throw new InventoryItemNotFoundException(productId);

                    await action(item);
                }, ct);
            }
            catch (DbUpdateConcurrencyException ex)
            {
                _logger.LogError(ex,
                    "Failed to {Operation} stock for ProductId {ProductId} after all retry attempts.",
                    operation, productId);

                throw new InsufficientStockException(productId, qty, 0);
            }
        }

    }
}
