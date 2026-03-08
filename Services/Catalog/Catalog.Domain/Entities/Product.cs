using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Catalog.Domain.Entities
{

    public class Product
    {
        public Guid Id { get; private set; }

        public string Name { get; private set; }

        public string? Description { get; private set; }

        public decimal Price { get; private set; }

        public Brand Brand { get; private set; }

        public Category Category { get; private set; }

        private readonly List<ProductImage> _images = [];

        public string ImageUrl { get; private set; }

        public bool IsActive { get; private set; }
        public bool IsDeleted { get; private set; }

        public DateTimeOffset CreatedAt { get; private set; }

        public DateTimeOffset UpdatedAt { get; private set; }

        private Product() { }



        public Product(
            Guid id,
            string name,
            decimal price,
            Brand brand,
            Category category,
            string? description,
            string imageUrl
            )
        {
            Id = id;
            Name = name;
            Price = price;
            Brand = brand;
            Category = category;
            Description = description;
            ImageUrl = imageUrl;

            IsActive = true;
            IsDeleted = false;
            CreatedAt = DateTime.UtcNow;
        }

        //public void AddImage(string url, int sortOrder)
        //{
        //    _images.Add(new ProductImage(Guid.NewGuid(), url, sortOrder));
        //    UpdatedAt = DateTime.UtcNow;
        //}

        public void UpdateDetails(string name, string? description, decimal price,Brand brand,Category category,string imageUrl)
        {
            Name = name;
            Description = description;
            Price = price;
            Brand = brand;
            Category = category;
            ImageUrl = imageUrl;
            UpdatedAt = DateTimeOffset.UtcNow;

            // TODO: later we may add domain events if needed
        }

        public void ToggleActivation(bool isActive)
        {
            IsActive = isActive;
            UpdatedAt = DateTimeOffset.UtcNow;
        }

        public void SoftDelete()
        {
            IsDeleted = true;
            UpdatedAt = DateTimeOffset.UtcNow;
        }
    }
}
