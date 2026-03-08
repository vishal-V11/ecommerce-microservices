using Catalog.Application.Abstractions;
using Catalog.Application.Common.DTO;
using MediatR;

namespace Catalog.Application.Features.Products.Queries.GetProductById
{
    public sealed class GetProductByIdQueryHandler : IRequestHandler<GetProductByIdQuery, ProductDetailDto?>
    {

        private readonly IProductReadRepository _productRepository;

        public GetProductByIdQueryHandler(IProductReadRepository productRepository)
        {
            _productRepository = productRepository;
        }
        public async Task<ProductDetailDto?> Handle(GetProductByIdQuery request, CancellationToken ct)
        {
            return await _productRepository.GetByIdAsync(request.ProductId, ct);
        }
    }
}
