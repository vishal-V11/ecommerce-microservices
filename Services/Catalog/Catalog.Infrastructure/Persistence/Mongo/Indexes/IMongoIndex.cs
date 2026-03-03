using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Catalog.Infrastructure.Persistence.Mongo.Indexes
{
    public interface IMongoIndex
    {
        Task CreateAsync(CancellationToken cancellationToken = default);
    }
}
