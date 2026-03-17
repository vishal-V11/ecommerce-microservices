using Inventory.API.Entities;
using Microsoft.EntityFrameworkCore;

namespace Inventory.API.Persistence
{
    public class InventoryDbContext:DbContext
    {
        public InventoryDbContext(DbContextOptions<InventoryDbContext> options):base(options)
        {
            
        }

        public DbSet<InventoryItem> InventoryItems => Set<InventoryItem>();
        public DbSet<ProcessedEvent> ProcessedEvents => Set<ProcessedEvent>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<InventoryItem>(builder =>
            {
                builder.ToTable("inventory_items");
                builder.HasKey(x => x.ProductId);

                //snake case (Postgresql naming convention)
                builder.Property(x => x.ProductId)
                .HasColumnName("product_id")
                .ValueGeneratedNever();

                builder.Property(x => x.StockQty)
                .HasColumnName("stock_qty")
                .IsRequired()
                .HasDefaultValue(0);

                builder.Property(x => x.ReservedQty)
                .HasColumnName("reserved_qty")
                .IsRequired()
                .HasDefaultValue(0);

                builder.Property(x => x.Version)
                .HasColumnName("version")
                .IsRequired()
                .HasDefaultValue(0)
                .IsConcurrencyToken();

                builder.Property(x => x.LastUpdatedAt)
               .HasColumnName("last_updated_at")
               .IsRequired();

            });

            modelBuilder.Entity<ProcessedEvent>(builder =>
            {
                builder.ToTable("processed_events");

                builder.HasKey(x => x.EventId);

                builder.Property(x => x.EventId)
                .HasColumnName("event_id")
                .ValueGeneratedNever();

                builder.Property(x => x.EventType)
                    .HasColumnName("event_type")
                    .IsRequired();

                builder.Property(x => x.ProcessedAt)
                .HasColumnName("processed_at")
                .IsRequired();
            });
        }
    }
}
