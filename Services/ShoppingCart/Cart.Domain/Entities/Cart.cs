using System.Text.Json.Serialization;
using Cart.Domain.Exceptions;

namespace Cart.Domain.Entities
{
    public class Cart
    {
        public string UserId { get; private set; }
        public List<CartItem> Items { get; private set; } = new();

        public DateTimeOffset LastModified { get; private set; }

        [JsonConstructor]
        public Cart(string userId, List<CartItem> items, DateTime lastModified)
        {
            UserId = userId;
            Items = items;
            LastModified = lastModified;
        }

        public Cart(string userId)
        {
            UserId = userId;
            LastModified = DateTimeOffset.UtcNow;
        }

        // CartItem is always created internally — only Cart controls its children
        public void AddItem(Guid productId, string productName, decimal unitPrice)
        {
            var existing = Items.FirstOrDefault(i => i.ProductId == productId);

            if (existing is not null)
                existing.Quantity++;
            else
                Items.Add(new CartItem(productId, productName, unitPrice));

            LastModified = DateTime.UtcNow;
        }

        public void IncrementItem(Guid productId, int quantity)
        {
            var item = Items.FirstOrDefault(i => i.ProductId == productId)
                ?? throw new CartItemNotFoundException(productId);

            item.Quantity += quantity;
            LastModified = DateTime.UtcNow;
        }

        public void DecrementItem(Guid productId, int quantity)
        {
            var item = Items.FirstOrDefault(i => i.ProductId == productId)
                ??throw new CartItemNotFoundException(productId);

            if (item.Quantity <= quantity)
                Items.Remove(item);
            else
                item.Quantity -= quantity;

            LastModified = DateTime.UtcNow;
        }

        public void RemoveItem(Guid productId)
        {
            var item = Items.FirstOrDefault(i => i.ProductId == productId)
                ?? throw new CartItemNotFoundException(productId);

            Items.Remove(item);
            LastModified = DateTime.UtcNow;
        }


        public decimal TotalPrice => Items.Sum(x => x.TotalPrice);
    }
}
