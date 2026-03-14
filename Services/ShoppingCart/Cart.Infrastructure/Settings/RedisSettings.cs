using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cart.Infrastructure.Settings
{
    public class RedisSettings
    {
        public string ConnectionString { get; set; } = default!;
    }
}
