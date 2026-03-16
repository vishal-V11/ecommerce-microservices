namespace Inventory.API.DTO
{
    public record AddStockRequest(Guid ProductId,int Qty);
}
