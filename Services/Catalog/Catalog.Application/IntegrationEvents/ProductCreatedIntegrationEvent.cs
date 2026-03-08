namespace Catalog.Application.IntegrationEvents
{
    public sealed record ProductCreatedIntegrationEvent(
        Guid ProductId,
        Guid BrandId,
        Guid CategoryId,
        string Name,
        decimal Price
    );
}
