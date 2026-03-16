namespace Inventory.API.Interfaces
{
    public interface IProcessedEventsRepository
    {
        Task<bool> ExistsAsync(Guid eventId,CancellationToken ct);
        Task AddAsync(Guid eventId, CancellationToken ct);
    }
}
