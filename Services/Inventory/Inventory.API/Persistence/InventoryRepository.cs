using Inventory.API.Entities;
using Inventory.API.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace Inventory.API.Persistence
{
    public class InventoryRepository : IInventoryRepository
    {
        private readonly InventoryDbContext _context;

        public InventoryRepository(InventoryDbContext context)
        {
            _context = context;
        }
        public Task<InventoryItem?> GetByProductIdAsync(Guid ProductId, CancellationToken ct)
        {
            return _context.InventoryItems.FirstOrDefaultAsync(x => x.ProductId == ProductId, ct);
        }
        public async Task AddAsync(InventoryItem item, CancellationToken ct)
        {
            await _context.InventoryItems.AddAsync(item, ct);
            await _context.SaveChangesAsync(ct);
        }


        public async Task UpdateAsync(InventoryItem item, CancellationToken ct = default)
        {
            _context.InventoryItems.Update(item);
            await _context.SaveChangesAsync(ct);
        }
    }
}
