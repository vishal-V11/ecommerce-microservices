using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Catalog.Infrastructure.Settings
{
    public sealed class RedisSettings
    {
        public string ConnectionString { get; set; } = default!;
    }
}
