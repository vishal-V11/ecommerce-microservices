using Ordering.Domain.Enums;

namespace Ordering.Domain.Exceptions
{
    public class InvalidOrderStatusTransitionException:Exception
    {
        public InvalidOrderStatusTransitionException(Guid orderId,OrderStatus current, OrderStatus attempted)
            : base
            ($"Order '{orderId}' cannot transition from '{current}' to '{attempted}'.")
        {}
    }
}
