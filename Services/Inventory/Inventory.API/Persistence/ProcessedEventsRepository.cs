using Inventory.API.Entities;
using Inventory.API.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace Inventory.API.Persistence
{
    public class ProcessedEventsRepository : IProcessedEventsRepository
    {
        private readonly InventoryDbContext _context;
        public ProcessedEventsRepository(InventoryDbContext context)
        {
            _context = context;
        }
        public async Task<bool> ExistsAsync(Guid eventId,string eventType, CancellationToken ct)
        {
            return await _context.ProcessedEvents.AnyAsync(x=>x.EventId == eventId && x.EventType == eventType,ct);
        }
        public async Task AddAsync(Guid eventId,string eventType, CancellationToken ct)
        {
            ProcessedEvent processedEvent = ProcessedEvent.Create(eventId,eventType);
            await _context.ProcessedEvents.AddAsync(processedEvent,ct);
            await _context.SaveChangesAsync(ct);
        }
    }
}
