namespace Shared.Messaging.Constants
{
    public static class KafkaGroups
    {
        public const string InventoryService = "inventory-service";
        // Order Service — Saga consumer group
        public const string OrderService = "order-service";

        // Payment Service — consumes PaymentProcessRequested
        public const string PaymentService = "payment-service";

        // Cart Service — consumes CartClear
        public const string CartService = "cart-service";

        // Notification Service — consumes SendNotification
        public const string NotificationService = "notification-service";
    }
}
