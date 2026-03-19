using Microsoft.EntityFrameworkCore;
using Payment.API.Abstraction;
using Payment.API.Data;

namespace Payment.API.Repositories
{
    public class PaymentRepository:IPaymentRepository
    {
        private readonly PaymentDbContext _context;

        public PaymentRepository(PaymentDbContext context)
        {
            _context = context;
        }

        public async Task<bool> ExistsAsync(Guid correlationId, CancellationToken ct = default)
        {
            return await _context.Payments.AnyAsync(p => p.CorrelationId == correlationId, ct);
        }

        public async Task AddAsync(Entities.Payment payment, CancellationToken ct = default)
        {
            await _context.Payments.AddAsync(payment, ct);
            await _context.SaveChangesAsync(ct);
        }
    }
}
