namespace Inventory.API.Interfaces
{
    public interface IProcessedEventsRepository
    {
        Task<bool> ExistsAsync(Guid eventId,string eventType,CancellationToken ct);
        Task AddAsync(Guid eventId,string eventType, CancellationToken ct);
    }
}
