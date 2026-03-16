namespace Inventory.API.Exceptions
{
    public class InventoryItemNotFoundException:Exception
    {
        public InventoryItemNotFoundException(Guid productId)
            :base($"Inventory with Product {productId} not found")
        {
            
        }
    }
}
