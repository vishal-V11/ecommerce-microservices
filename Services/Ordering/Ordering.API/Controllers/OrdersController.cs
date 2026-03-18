using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Ordering.Application.Common.DTOs;
using Ordering.Application.Features.Commands.PlaceOrder;
using Ordering.Application.Features.Queries.GetOrderById;
using Ordering.Application.Features.Queries.GetOrdersByUser;

namespace Ordering.API.Controllers
{

    [Route("api/[controller]")]
    [ApiController]
    [Authorize]

    public sealed class OrdersController : ControllerBase
    {
        private readonly IMediator _mediator;

        public OrdersController(IMediator mediator)
        {
            _mediator = mediator;   
        }
        /// <summary>
        /// Places a new order for the authenticated user.
        /// Persists the order and kicks off the Saga via OrderCreatedEvent.
        /// </summary>
        [HttpPost]
        [ProducesResponseType(typeof(OrderDto), StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> PlaceOrder(
            [FromBody] PlaceOrderCommand command,
            CancellationToken ct)
        {
            var order = await _mediator.Send(command, ct);
            return CreatedAtAction(nameof(GetOrderById), new { orderId = order.OrderId }, order);
        }

        /// <summary>
        /// Returns a single order by ID.
        /// Only the order owner can access their order.
        /// </summary>
        [HttpGet("getOrderDetail{orderId:guid}")]
        [ProducesResponseType(typeof(OrderDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> GetOrderById(
            Guid orderId,
            CancellationToken ct)
        {
            var order = await _mediator.Send(new GetOrderByIdQuery(orderId), ct);
            return Ok(order);
        }

        /// <summary>
        /// Returns all orders for the authenticated user.
        /// UserId is resolved from JWT claims via IUserContext.
        /// </summary>
        [HttpGet("getUserOrders")]
        [ProducesResponseType(typeof(IReadOnlyList<OrderDto>), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> GetOrdersByUser(CancellationToken ct)
        {
            var orders = await _mediator.Send(new GetOrdersByUserQuery(), ct);
            return Ok(orders);
        }


    }
}
