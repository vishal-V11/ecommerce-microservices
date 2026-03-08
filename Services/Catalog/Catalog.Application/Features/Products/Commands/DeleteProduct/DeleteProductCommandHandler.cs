using Catalog.Application.Abstractions;
using Catalog.Application.Common.Responses;
using Catalog.Application.Exceptions;
using MediatR;

namespace Catalog.Application.Features.Products.Commands.DeleteProduct
{
    public class DeleteProductCommandHandler : IRequestHandler<DeleteProductCommand, Result>
    {

        private readonly IProductRepository _products;
        private readonly IUnitOfWork _unitOfWork;
        public DeleteProductCommandHandler(IProductRepository products
            , IUnitOfWork unitOfWork)
        {
            _products = products;
            _unitOfWork = unitOfWork;

        }

        public async Task<Result> Handle(DeleteProductCommand request, CancellationToken ct)
        {
            var product = await _products.GetByIdAsync(request.ProductId, ct)
               ?? throw new NotFoundException($"Product {request.ProductId} not found");

            await _unitOfWork.ExecuteAsync(async token =>
            {
                await _products.DeleteAsync(request.ProductId, token);
            }, ct);

            return Result.Success();
        }
    }
}
