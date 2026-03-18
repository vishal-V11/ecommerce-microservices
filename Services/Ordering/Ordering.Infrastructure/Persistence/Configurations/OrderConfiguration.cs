using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Ordering.Domain.Entities;

namespace Ordering.Infrastructure.Persistence.Configurations
{
    public class OrderConfiguration : IEntityTypeConfiguration<Order>
    {
        public void Configure(EntityTypeBuilder<Order> builder)
        {
            builder.ToTable("orders");

            builder.HasKey(x=>x.OrderId);
            builder.Property(o => o.OrderId).HasColumnName("order_id");

            builder.Property(o => o.UserId).HasColumnName("user_id").IsRequired();
            builder.Property(o => o.Status).HasColumnName("status").HasConversion<string>();
            builder.Property(o => o.PaymentMethod).HasColumnName("payment_method").HasConversion<string>();
            builder.Property(o => o.TotalAmount).HasColumnName("total_amount").HasColumnType("numeric(18,2)");
            builder.Property(o => o.CreatedAt).HasColumnName("created_at");

            // Ignore computed property — derived from Items
            builder.Ignore(o => o.TotalAmount);

            builder.OwnsOne(o => o.DeliveryAddress, da =>
            {
                da.Property(d => d.FullName).HasColumnName("delivery_full_name").IsRequired();
                da.Property(d => d.AddressLine1).HasColumnName("delivery_address_line1").IsRequired();
                da.Property(d => d.AddressLine2).HasColumnName("delivery_address_line2");
                da.Property(d => d.City).HasColumnName("delivery_city").IsRequired();
                da.Property(d => d.State).HasColumnName("delivery_state").IsRequired();
                da.Property(d => d.Pincode).HasColumnName("delivery_pincode").IsRequired();
                da.Property(d => d.PhoneNumber).HasColumnName("delivery_phone_number").IsRequired();
            });

            builder.HasMany(o => o.Items)
           .WithOne()
           .HasForeignKey(i => i.OrderId)
           .OnDelete(DeleteBehavior.Cascade);

            // Bind private backing field
            builder.Navigation(o => o.Items).HasField("_items");
        }
    }
}
