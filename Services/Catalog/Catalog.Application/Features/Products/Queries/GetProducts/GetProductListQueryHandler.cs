using Catalog.Application.Abstractions;
using Catalog.Application.Common.DTO;
using Catalog.Application.Common.Responses;
using MediatR;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Catalog.Application.Features.Products.Queries.SearchProducts
{
    public sealed class GetProductListQueryHandler : IRequestHandler<GetProductListQuery, PagedResult<ProductListVm>>
    {
        private readonly IProductReadRepository _productRepository;

        public GetProductListQueryHandler(IProductReadRepository productRepository)
        {
            _productRepository = productRepository;
        }
        public async Task<PagedResult<ProductListVm>> Handle(GetProductListQuery request, CancellationToken cancellationToken)
        {
            return await _productRepository.GetPagedAsync(request, cancellationToken);
        }
    }
}
