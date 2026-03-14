using System.Text.Json.Serialization;

namespace Cart.Domain.Entities
{
    public class CartItem
    {
        public Guid ProductId { get; private set; }
        public string ProductName { get; private set; }
        public decimal UnitPrice { get; private set; }
        public int Quantity { get;internal set; }
        public decimal TotalPrice => UnitPrice * Quantity;

        [JsonConstructor]
        internal CartItem(Guid productId, string productName, decimal unitPrice, int quantity)
        {
            ProductId = productId;
            ProductName = productName;
            UnitPrice = unitPrice;
            Quantity = quantity;
        }

        internal CartItem(Guid productId, string productName, decimal unitPrice)
        {
            if (unitPrice < 0) throw new ArgumentException("Unit Price cannot be negative");

            ProductId = productId;
            ProductName = productName;
            UnitPrice = unitPrice;
            Quantity = 1;

        }


        
    }
}
