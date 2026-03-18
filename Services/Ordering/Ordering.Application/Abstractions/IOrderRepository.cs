using Ordering.Domain.Entities;

namespace Ordering.Application.Abstractions
{
    public interface IOrderRepository
    {
        Task<Order?> GetByIdAsync(Guid orderId, CancellationToken ct);
        Task AddAsync(Order order, CancellationToken ct);
        Task SaveChangesAsync(CancellationToken ct);
        Task<IReadOnlyList<Order>> GetByUserIdAsync(string userId,CancellationToken ct);
    }
}
