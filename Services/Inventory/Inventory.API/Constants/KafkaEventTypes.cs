namespace Inventory.API.Constants
{
    public static class KafkaEventTypes
    {
        public const string ProductCreated = "ProductCreated";
        public const string StockLockRequested = "StockLockRequested";
        public const string StockReleaseRequested = "StockReleaseRequested";
        public const string StockConfirmRequested = "StockConfirmRequested";
    }
}
