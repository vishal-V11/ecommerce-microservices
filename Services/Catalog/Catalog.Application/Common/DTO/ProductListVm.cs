namespace Catalog.Application.Common.DTO
{
    public record ProductListVm
    {
        public Guid ProductId { get; init; }

        public string Name { get; init; }

        public decimal Price { get; init; }

        public string BrandName { get; init; }

        public string CategoryName { get; init; }

        public bool IsActive { get; init; }
    }
}
