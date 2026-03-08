namespace Catalog.Domain.Entities
{
    public class Brand
    {
        public Guid Id { get; private set; }
        public string Name { get; private set; }

        public Brand(Guid brandId,string name)
        {
            Id = brandId;
            Name = name;
        }
    }
}
