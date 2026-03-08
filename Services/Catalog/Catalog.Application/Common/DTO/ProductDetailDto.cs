namespace Catalog.Application.Common.DTO
{
    public record ProductDetailDto
    {
        public Guid ProductId { get; init; }

        public required string Name { get; init; }

        public string? Description { get; init; }

        public decimal Price { get; init; }

        public required BrandDto Brand { get; init; }

        public required CategoryDto Category { get; init; }

        public string ImageUrl { get; init; }
    }
}
