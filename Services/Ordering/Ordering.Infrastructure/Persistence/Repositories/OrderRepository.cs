using Microsoft.EntityFrameworkCore;
using Ordering.Application.Abstractions;
using Ordering.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ordering.Infrastructure.Persistence.Repositories
{
    public class OrderRepository : IOrderRepository
    {
        private readonly OrderDbContext _context;
        public OrderRepository(OrderDbContext context)
        {
            _context = context;
        }

        public async Task<Order?> GetByIdAsync(Guid orderId, CancellationToken ct)
        {
            return await _context.Orders
                .Include(o => o.Items)
                .FirstOrDefaultAsync(o => o.OrderId == orderId, ct);

        }

        public async Task AddAsync(Order order, CancellationToken ct)
        {
            await _context.Orders.AddAsync(order, ct);
        }
            

        public Task SaveChangesAsync(CancellationToken ct)
            => _context.SaveChangesAsync(ct);

        public async Task<IReadOnlyList<Order>> GetByUserIdAsync(string UserId,CancellationToken ct)
        {
            return await _context.Orders.Where(x => x.UserId == UserId).Include(i=>i.Items).ToListAsync(ct);
        }

    }
}
