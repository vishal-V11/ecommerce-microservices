namespace Inventory.API.Entities
{
    public class ProcessedEvent
    {
        public Guid EventId { get; private set; }
        public string EventType { get; private set; } = null!;
        public DateTimeOffset ProcessedAt { get; private set; }
        private ProcessedEvent() { }

        public static ProcessedEvent Create(Guid eventId,string eventyType)
        {
            return new ProcessedEvent
            {
                EventId = eventId,
                EventType = eventyType,
                ProcessedAt = DateTime.UtcNow
            };
        }
    }
}
