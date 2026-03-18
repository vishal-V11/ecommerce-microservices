using MediatR;
using Ordering.Application.Common.DTOs;

namespace Ordering.Application.Features.Queries.GetOrderById
{
    public sealed record GetOrderByIdQuery(Guid OrderId) : IRequest<OrderDto>;
}
