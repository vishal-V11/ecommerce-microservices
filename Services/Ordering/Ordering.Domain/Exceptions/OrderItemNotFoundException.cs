namespace Ordering.Domain.Exceptions
{
    public class OrderItemNotFoundException:Exception
    {
        public OrderItemNotFoundException(Guid orderItemId) : base($"Order item '{orderItemId}' was not found.")
        {}
        
    }
}
