using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Catalog.Domain.Entities
{
    public class Brand
    {
        public Guid BrandId { get; private set; }
        public string Name { get; private set; }

        public Brand(Guid brandId,string name)
        {
            BrandId = brandId;
            Name = name;
        }
    }
}
