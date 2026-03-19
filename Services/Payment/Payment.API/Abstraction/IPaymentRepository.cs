namespace Payment.API.Abstraction
{
    public interface IPaymentRepository
    {
        Task<bool> ExistsAsync(Guid correlationId, CancellationToken ct = default);
        Task AddAsync(Entities.Payment payment, CancellationToken ct = default);
    }
}
