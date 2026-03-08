namespace Catalog.Application.Common.DTO
{
    public class ProductSearchVm
    {
        public Guid ProductId { get; init; }
        public string Name { get; init; }
        public decimal Price { get; init; }
        public string ImageUrl { get; init; }
        public string BrandName { get; init; }
        public DateTimeOffset CreatedAt { get; init; }
    }
}
