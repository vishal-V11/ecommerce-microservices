using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Catalog.Domain.Entities
{
    public class Category
    {
        public Guid CategoryId { get; private set; }
        public string Name { get; private set; }

        public Category(Guid categoryId,string name)
        {
            CategoryId = categoryId;
            Name = name; 
        }
    }
}
