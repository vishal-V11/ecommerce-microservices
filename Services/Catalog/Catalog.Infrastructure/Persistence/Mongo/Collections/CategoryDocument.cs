namespace Catalog.Infrastructure.Persistence.Mongo.Collections
{
    public  class CategoryDocument:BaseDocument
    {
        public Guid CategoryId { get; set; }
        public string Name { get; set; }
    }
}
