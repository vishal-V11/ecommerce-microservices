using Cart.Application.Common.DTOs;
using Cart.Application.Features.Commands.AddItem;
using Cart.Application.Features.Commands.ClearCart;
using Cart.Application.Features.Commands.DecrementItem;
using Cart.Application.Features.Commands.IncrementItem;
using Cart.Application.Features.Commands.RemoveItemCart;
using Cart.Application.Features.Queries.GetCart;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Cart.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public sealed class CartController : ControllerBase
    {
        private readonly IMediator _mediator;
        public CartController(IMediator mediator)
        {
            _mediator = mediator;
        }

        /// <summary>Get the current user's cart</summary>
        [HttpGet]
        [ProducesResponseType(typeof(CartDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<ActionResult<CartDto>> GetCart(CancellationToken ct)
        {
            var cart = await _mediator.Send(new GetCartQuery(), ct);
            return cart is null ? NoContent() : Ok(cart);
        }

        /// <summary>Add a product to the cart with quantity 1</summary>
        [HttpPost("items")]
        [ProducesResponseType(typeof(CartDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<ActionResult<CartDto>> AddItem([FromBody] AddItemRequest request,CancellationToken ct)
        {
            var cart = await _mediator.Send(
                new AddItemCommand(request.ProductId, request.ProductName, request.UnitPrice), ct);

            return Ok(cart);
        }

        /// <summary>Increment a cart item quantity</summary>
        [HttpPatch("items/increment")]
        [ProducesResponseType(typeof(CartDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<ActionResult<CartDto>> IncrementItem([FromBody] IncrementItemRequest request,CancellationToken ct)
        {
            var cart = await _mediator.Send(
                new IncrementItemCommand(request.ProductId, request.Quantity), ct);

            return Ok(cart);
        }

        /// <summary>Decrement a cart item quantity — auto removes if quantity hits 0</summary>
        [HttpPatch("items/decrement")]
        [ProducesResponseType(typeof(CartDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<ActionResult<CartDto>> DecrementItem(
            [FromBody] DecrementItemRequest request,
            CancellationToken ct)
        {
            var cart = await _mediator.Send(
                new DecrementItemCommand(request.ProductId, request.Quantity), ct);

            return Ok(cart);
        }

        /// <summary>Remove a product from the cart entirely</summary>
        [HttpDelete("items/{productId}")]
        [ProducesResponseType(typeof(CartDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<ActionResult<CartDto>> RemoveItem([FromRoute] Guid productId,CancellationToken ct)
        {
            var cart = await _mediator.Send(new RemoveItemCommand(productId), ct);
            return Ok(cart);
        }

        /// <summary>Clear all items from the cart</summary>
        [HttpDelete]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> ClearCart(CancellationToken ct)
        {
            await _mediator.Send(new ClearCartCommand(), ct);
            return NoContent();
        }

    }
}
