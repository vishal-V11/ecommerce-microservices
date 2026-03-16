namespace Inventory.API.Entities
{
    public class ProcessedEvent
    {
        public Guid EventId { get; private set; }
        public DateTimeOffset ProcessedAt { get; private set; }
        private ProcessedEvent() { }

        public static ProcessedEvent Create(Guid eventId)
        {
            return new ProcessedEvent
            {
                EventId = eventId,
                ProcessedAt = DateTime.UtcNow
            };
        }
    }
}
