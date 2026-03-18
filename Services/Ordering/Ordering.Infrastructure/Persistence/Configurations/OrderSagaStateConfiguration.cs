using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Ordering.Infrastructure.Saga;

namespace Ordering.Infrastructure.Persistence.Configurations
{
    public class OrderSagaStateConfiguration : IEntityTypeConfiguration<OrderSagaState>
    {
        public void Configure(EntityTypeBuilder<OrderSagaState> builder)
        {
            builder.ToTable("order_saga_states");

            builder.HasKey(s => s.CorrelationId);
            builder.Property(s => s.CorrelationId).HasColumnName("correlation_id");
            builder.Property(s => s.OrderId).HasColumnName("order_id");
            builder.Property(s => s.UserId).HasColumnName("user_id");
            builder.Property(s => s.CurrentState).HasColumnName("current_state").IsRequired();
            builder.Property(s => s.CreatedAt).HasColumnName("created_at");

            // Optimistic concurrency
            builder.Property(s => s.RowVersion)
                .HasColumnName("row_version")
                .IsRowVersion()
                .IsConcurrencyToken();
        }
    }
}
