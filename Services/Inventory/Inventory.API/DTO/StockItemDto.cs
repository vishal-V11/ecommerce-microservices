namespace Inventory.API.DTO
{
    public sealed record StockItemDto(Guid ProductId, int Quantity);
}
