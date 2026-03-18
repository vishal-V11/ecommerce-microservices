using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Ordering.Domain.Entities;

namespace Ordering.Infrastructure.Persistence.Configurations
{
    public class OrderItemConfiguration : IEntityTypeConfiguration<OrderItem>
    {
        public void Configure(EntityTypeBuilder<OrderItem> builder)
        {
            builder.ToTable("order_items");

            builder.HasKey(i => i.OrderItemId);
            builder.Property(i => i.OrderItemId).HasColumnName("order_item_id");
            builder.Property(i => i.OrderId).HasColumnName("order_id");
            builder.Property(i => i.ProductId).HasColumnName("product_id");
            builder.Property(i => i.ProductName).HasColumnName("product_name").IsRequired();
            builder.Property(i => i.UnitPrice).HasColumnName("unit_price").HasColumnType("numeric(18,2)");
            builder.Property(i => i.Quantity).HasColumnName("quantity");

            // Ignore computed property — derived from UnitPrice * Quantity
            builder.Ignore(i => i.TotalPrice);
        }
    }
}
