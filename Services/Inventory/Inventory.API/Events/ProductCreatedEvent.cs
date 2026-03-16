namespace Inventory.API.Events
{
    public sealed record ProductCreatedEvent(
         Guid ProductId,
         Guid BrandId,
         Guid CategoryId,
         string Name,
         decimal Price
    );
}
