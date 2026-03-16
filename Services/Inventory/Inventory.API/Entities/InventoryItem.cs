using Inventory.API.Exceptions;

namespace Inventory.API.Entities
{
    public class InventoryItem
    {
        public Guid ProductId { get; private set; }
        public int StockQty { get; private set; }
        public int ReservedQty { get; private set; }
        public int Version { get; private set; }
        public DateTimeOffset LastUpdatedAt { get; private set; }

        public int AvailableQty => StockQty - ReservedQty;

        private InventoryItem() { }

        public static InventoryItem Create(Guid productId)
        {
            return new InventoryItem
            {
                ProductId = productId,
                StockQty = 1000,
                ReservedQty = 0,
                Version = 0,
                LastUpdatedAt = DateTimeOffset.UtcNow
            };
        }
        
        public void AddStock(int qty)
        {
            if (qty <= 0) throw new ArgumentException("Quantity must be greater than zero.");
            StockQty += qty;
            BumpVersion();
        }

        public void LockStock(int qty)
        {
            if (qty <= 0) throw new ArgumentException("Quantity must be greater than zero.");
            if (AvailableQty < qty) throw new InsufficientStockException(ProductId, qty, AvailableQty);
            ReservedQty += qty;
            BumpVersion();
        }

        public void ReleaseStock(int qty)
        {
            if (qty <= 0) throw new ArgumentException("Quantity must be greater than zero.");
            ReservedQty = Math.Max(0, ReservedQty - qty);
            BumpVersion();
        }

        public void ConfirmStock(int qty)
        {
            if (qty <= 0) throw new ArgumentException("Quantity must be greater than zero.");
            StockQty -= qty;
            ReservedQty = Math.Max(0, ReservedQty - qty);
            BumpVersion();
        }

        private void BumpVersion()
        {
            Version++;
            LastUpdatedAt = DateTimeOffset.UtcNow;
        }
    }
}
