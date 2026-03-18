using Microsoft.EntityFrameworkCore;

namespace Payment.API.Data
{
    public class PaymentDbContext:DbContext
    {
        public DbSet<Entities.Payment> Payments => Set<Entities.Payment>();
        public PaymentDbContext(DbContextOptions<PaymentDbContext> options):base(options) {}

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {

            modelBuilder.Entity<Entities.Payment>(entity =>
            {
                entity.HasKey(p => p.PaymentId);
                entity.HasIndex(p => p.CorrelationId).IsUnique();
                entity.Property(p => p.Amount).HasPrecision(18, 2);
                entity.Property(p => p.PaymentMethod).HasConversion<string>();
                entity.Property(p => p.Status).HasConversion<string>();
            });
        }
    }
}
