using Catalog.Application.Features.Products.Commands.CreateProduct;
using Catalog.Application.Features.Products.Commands.DeleteProduct;
using Catalog.Application.Features.Products.Commands.UpdateProduct;
using Catalog.Application.Features.Products.Queries.GetProductById;
using Catalog.Application.Features.Products.Queries.SearchProducts;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Catalog.API.Controllers
{
    [Route("api/v{version:apiVersion}/[controller]")]
    [ApiVersion("1.0")]
    [ApiController]
    [Authorize]
    public class ProductsController : ControllerBase
    {
        private readonly IMediator _mediator;
        public ProductsController(IMediator mediator)
        {
            _mediator = mediator;
        }

        [HttpPost("createProduct")]
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> CreateProduct([FromBody] CreateProductCommand command)
        {
            var response = await _mediator.Send(command);
            if (!response.IsSuccess)
                return BadRequest(response);

            return CreatedAtAction(
                nameof(GetProductById),
                new { id = response.Data },
                response
            );

        }

        [HttpPut("update")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public async Task<IActionResult> UpdateProduct(UpdateProductCommand command, CancellationToken cancellationToken)
        {
            var result = await _mediator.Send(command, cancellationToken);

            return Ok(result);
        }

        [HttpDelete("{id}")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> DeleteProduct(Guid id)
        {
            var result = await _mediator.Send(new DeleteProductCommand(id));
            return Ok(id);
        }

        [HttpGet("{id}")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> GetProductById(Guid id, CancellationToken cancellationToken)
        {
            var result = await _mediator.Send(new GetProductByIdQuery(id), cancellationToken);
            if(result != null)
                return Ok(result);

            return NotFound(new {Message = $"Product with ID {id} not found" });
        }


        [HttpGet("getAdminProducts")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public async Task<IActionResult> GetAdminProducts([FromQuery] GetProductListQuery query, CancellationToken ct)
        {
            return Ok(await _mediator.Send(query,ct));
        }

        [HttpGet("search")]
        public async Task<IActionResult> Search([FromQuery] SearchProductsQuery query, CancellationToken ct)
        {
            return Ok(await _mediator.Send(query, ct));
        }
    }
}
