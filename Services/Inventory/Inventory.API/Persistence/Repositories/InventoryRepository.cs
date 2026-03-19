using Inventory.API.Entities;
using Inventory.API.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace Inventory.API.Persistence.Repositories
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

        public async Task<List<InventoryItem>> GetByIdAsync(List<Guid> productIds, CancellationToken ct)
        {
            //return await (from item in _context.InventoryItems
            //            join id in productIds on item.ProductId equals id 
            //            select item
            //            ).ToListAsync(ct);   

            return await _context.InventoryItems
                        .Join(productIds,
                            item => item.ProductId,
                            id => id,
                            (item, _) => item)
                        .ToListAsync(ct);
        }

        public async Task AddAsync(InventoryItem item, CancellationToken ct)
        {
            await _context.InventoryItems.AddAsync(item, ct);
            await SaveChangesAsync(ct);
        }


        public async Task UpdateAsync(InventoryItem item, CancellationToken ct = default)
        {
            _context.InventoryItems.Update(item);
            await SaveChangesAsync(ct);
        }

        public async Task SaveChangesAsync(CancellationToken ct = default)
        {
            await _context.SaveChangesAsync(ct);
        }

    }
}
