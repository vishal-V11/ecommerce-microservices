using MediatR;
using Ordering.Application.Common.DTOs;

namespace Ordering.Application.Features.Queries.GetOrdersByUser
{
    public sealed record GetOrdersByUserQuery : IRequest<IReadOnlyList<OrderDto>>;
}
