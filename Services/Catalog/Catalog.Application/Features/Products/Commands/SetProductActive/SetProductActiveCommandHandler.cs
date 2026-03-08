using Catalog.Application.Abstractions;
using Catalog.Application.Common.Responses;
using Catalog.Application.Exceptions;
using MediatR;

namespace Catalog.Application.Features.Products.Commands.SetProductActive
{
    public sealed class SetProductActiveCommandHandler
    : IRequestHandler<SetProductActiveCommand, Result>
    {
        private readonly IProductRepository _products;
        private readonly IUnitOfWork _unitOfWork;

        public SetProductActiveCommandHandler(
            IProductRepository products,
            IUnitOfWork unitOfWork)
        {
            _products = products;
            _unitOfWork = unitOfWork;
        }

        public async Task<Result> Handle(SetProductActiveCommand request, CancellationToken ct)
        {
            var product = await _products.GetByIdAsync(request.ProductId, ct)
               ?? throw new NotFoundException($"Product {request.ProductId} not found");

            product.ToggleActivation(request.IsActive);

            await _unitOfWork.ExecuteAsync(async token =>
            {
                await _products.SetActiveAsync(request.ProductId, request.IsActive, token);
            }, ct);

            return Result.Success();
        }
    }
}
