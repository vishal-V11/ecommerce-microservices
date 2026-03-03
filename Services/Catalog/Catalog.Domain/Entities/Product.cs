using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Catalog.Domain.Entities
{
    public class Product
    {
        public Guid ProductId { get; private set; }
        public string Name { get; private set; }
        public string Description { get; private set; }
        public string Summary { get; private set; }
        public decimal Price { get; private set; }
        public Brand Brand { get; private set; }
        public Category Category { get; set; }

        public bool IsDeleted { get; private set; }

        public Product(Guid productId, string name,string description,string summary, decimal price,
           Brand brand, Category category)
        {
            ProductId = productId;
            Name = name;
            Description = description;
            Summary = summary;
            Price = price;
            Brand = brand;
            Category = category;
            IsDeleted = false;
        }

        public void SoftDelete()
        {
            IsDeleted = true;
        }
    }
}
