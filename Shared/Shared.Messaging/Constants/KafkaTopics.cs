namespace Shared.Messaging.Constants
{
    public static class KafkaTopics
    {
        public const string ProductCreated = "catalog.product.created";

        // Order
        public const string OrderCreated = "order.order.created";

        // Stock
        public const string StockLockRequested = "order.stock.lock-requested";
        public const string StockLocked = "order.stock.locked";
        public const string StockLockFailed = "order.stock.lock-failed";
        public const string StockConfirm = "order.stock.confirm";
        public const string StockRelease = "order.stock.release";

        // Payment
        public const string PaymentProcessRequested = "order.payment.process-requested";
        public const string PaymentSucceeded = "order.payment.succeeded";
        public const string PaymentFailed = "order.payment.failed";

        // Cart
        public const string CartClear = "order.cart.clear";

        // Notification
        public const string SendNotification = "order.notification.send";
    }
}
