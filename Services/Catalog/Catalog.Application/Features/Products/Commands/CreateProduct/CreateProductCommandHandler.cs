using Catalog.Application.Abstractions;
using Catalog.Application.Common.Outbox;
using Catalog.Application.Common.Responses;
using Catalog.Application.Exceptions;
using Catalog.Application.IntegrationEvents;
using Catalog.Domain.Entities;
using MediatR;
using Shared.Messaging.Constants;
using Microsoft.Extensions.Logging;
using System.Text.Json;

namespace Catalog.Application.Features.Products.Commands.CreateProduct
{
    public class CreateProductCommandHandler : IRequestHandler<CreateProductCommand, Result<Guid>>
    {
        private readonly ILogger<CreateProductCommandHandler> _logger;
        private readonly IProductRepository _products;
        private readonly IBrandRepository _brands;
        private readonly ICategoryRepository _categories;
        private readonly IOutboxRepository _outbox;
        private readonly IUnitOfWork _unitOfWork;
        private readonly ICorrelationContext _correlationContext;

        public CreateProductCommandHandler(
            ILogger<CreateProductCommandHandler> logger,
            IProductRepository products,
            IBrandRepository brands,
            ICategoryRepository categories,
            IOutboxRepository outbox,
            IUnitOfWork unitOfWork,
            ICorrelationContext correlationContext
            )
        {
            _logger = logger;
            _products = products;
            _brands = brands;
            _categories = categories;
            _outbox = outbox;
            _unitOfWork = unitOfWork;
            _correlationContext = correlationContext;
        }
        public async Task<Result<Guid>> Handle(CreateProductCommand request, CancellationToken ct)
        {
            var brand = await _brands.GetByIdAsync(request.BrandId, ct)
                ?? throw new NotFoundException($"Brand not found with brandID: {request.BrandId.ToString()}");

            var category = await _categories.GetByIdAsync(request.CategoryId, ct)
                ?? throw new NotFoundException($"Category not found with categoryID: {request.CategoryId.ToString()}");

            var product = new Product(
                Guid.NewGuid(),
                request.Name,
                request.Price,
                brand,
                category,
                request.Description,
                request.ImageUrl
            );

            var integrationEvent = new ProductCreatedIntegrationEvent(
                product.Id,
                brand.Id,
                category.Id,
                product.Name,
                product.Price
            );

            var outboxMessage = new OutboxMessage
            (
                Guid.NewGuid(),
                KafkaTopics.ProductCreated,
                JsonSerializer.Serialize(integrationEvent),
                _correlationContext.CorrelationId,
                DateTimeOffset.UtcNow
            );

            await _unitOfWork.ExecuteAsync(async token =>
            {
                await _products.InsertAsync(product, token);

                await _outbox.AddAsync(outboxMessage, token);

            }, ct);

            return Result<Guid>.Success(product.Id);
        }
    }
}
