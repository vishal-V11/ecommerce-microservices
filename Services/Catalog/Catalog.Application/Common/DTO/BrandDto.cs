namespace Catalog.Application.Common.DTO
{
    public sealed record BrandDto
    {
        public Guid Id { get; set; }
        public required string Name { get; set; }
    }
}
