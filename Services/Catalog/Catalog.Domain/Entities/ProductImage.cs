using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Catalog.Domain.Entities
{
    public class ProductImage
    {
        public Guid Id { get; private set; }

        public string Url { get; private set; }

        public int SortOrder { get; private set; }

        private ProductImage() { }

        public ProductImage(Guid id, string url, int sortOrder)
        {
            Id = id;
            Url = url;
            SortOrder = sortOrder;
        }
    }
}
