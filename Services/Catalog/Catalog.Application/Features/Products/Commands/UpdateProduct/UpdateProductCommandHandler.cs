using Catalog.Application.Abstractions;
using Catalog.Application.Common.Responses;
using Catalog.Application.Exceptions;
using MediatR;
using Microsoft.Extensions.Logging;

namespace Catalog.Application.Features.Products.Commands.UpdateProduct
{
    public sealed class UpdateProductCommandHandler : IRequestHandler<UpdateProductCommand, Result>
    {

        private readonly IProductRepository _products;
        private readonly IBrandRepository _brandRepository;
        private readonly ICategoryRepository _categoryRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly ILogger<UpdateProductCommandHandler> _logger;

        public UpdateProductCommandHandler(IProductRepository products,
            IBrandRepository brandRepository,
            ICategoryRepository categoryRepository,
            IUnitOfWork unitOfWork,
            ILogger<UpdateProductCommandHandler> logger
            )
        {
            _products = products;
            _brandRepository = brandRepository;
            _categoryRepository = categoryRepository;
            _unitOfWork = unitOfWork;
            _logger = logger;
        }

        public async Task<Result> Handle(UpdateProductCommand request, CancellationToken ct)
        {

            _logger.LogInformation("Updating product {ProductId}",request.ProductId);

            var product = await _products.GetByIdAsync(request.ProductId, ct)
                ?? throw new NotFoundException($"Product {request.ProductId} not found");

            var brand = await _brandRepository
            .GetByIdAsync(request.BrandId, ct);

            var category = await _categoryRepository
                .GetByIdAsync(request.CategoryId, ct);

            if (brand is null || category is null)
                throw new Exception("Invalid brand or category");

            product.UpdateDetails(
                request.Name,
                request.Description,
                request.Price,
                brand,
                category,
                request.ImagePath
            );

            await _unitOfWork.ExecuteAsync(async token =>
            {
                await _products.UpdateAsync(product, token);
            }, ct);

            _logger.LogInformation("Product {ProductId} updated", request.ProductId);

            return Result.Success("Product updated successfully");
        }
    }
}
