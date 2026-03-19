namespace Shared.Messaging.Events.Catalog
{
    public sealed record ProductCreatedEvent(
         Guid ProductId,
         Guid BrandId,
         Guid CategoryId,
         string Name,
         decimal Price
    );
}
