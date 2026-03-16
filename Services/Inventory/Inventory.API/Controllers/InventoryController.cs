using Inventory.API.DTO;
using Inventory.API.Interfaces;
using Inventory.API.Services;
using Microsoft.AspNetCore.Mvc;

namespace Inventory.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class InventoryController : ControllerBase
    {

        private readonly IInventoryService _inventoryService;

        public InventoryController(InventoryService inventoryService)
        {
            _inventoryService = inventoryService;
        }

        [HttpGet]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public async Task<IActionResult> GetAll(CancellationToken ct)
        {
            // TODO: add GetAllAsync to repository when needed
            return Ok();
        }

        [HttpGet("getProductStock/{productId:guid}")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> GetByProductId(Guid productId, CancellationToken ct)
        {
            var item = await _inventoryService.GetByProductIdAsync(productId, ct);
            return Ok(item);
        }

        [HttpPost("addProductStock")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> AddStock([FromBody] AddStockRequest request, CancellationToken ct)
        {
            await _inventoryService.AddStockAsync(request.ProductId, request.Qty, ct);
            return NoContent();
        }
    }
}
