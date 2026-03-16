namespace Inventory.API.Exceptions
{
    public class InsufficientStockException : Exception
    {
        public InsufficientStockException(Guid productId, int requested, int available)
            : base($"Insufficient stock for ProductId '{productId}'. Requested: {requested}, Available: {available}.")
        {

        }
    }
}
