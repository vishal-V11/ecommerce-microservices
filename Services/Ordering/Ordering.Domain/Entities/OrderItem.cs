namespace Ordering.Domain.Entities
{
    public sealed class OrderItem
    {
        public Guid OrderItemId { get; }
        public Guid OrderId { get; }
        public Guid ProductId { get; }
        public string ProductName { get; }
        public decimal UnitPrice { get; }
        public int Quantity { get; }
        public decimal TotalPrice => UnitPrice * Quantity;

        internal OrderItem(
            Guid orderId,
            Guid productId,
            string productName,
            decimal unitPrice,
            int quantity)
        {
            OrderItemId = Guid.NewGuid();
            OrderId = orderId;
            ProductId = productId;
            ProductName = productName;
            UnitPrice = unitPrice;
            Quantity = quantity;
        }


        //Empty constructor for EF Core
        private OrderItem() { }
    }
}
