namespace Catalog.Domain.Entities
{
    public class Category
    {
        public Guid Id { get; private set; }
        public string Name { get; private set; }

        public Category(Guid categoryId,string name)
        {
            Id = categoryId;
            Name = name; 
        }
    }
}
