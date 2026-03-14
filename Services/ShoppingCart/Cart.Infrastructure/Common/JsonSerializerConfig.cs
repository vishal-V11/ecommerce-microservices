using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Cart.Infrastructure.Common
{
    /// <summary>
    /// A static class to provide default Config for Serialization/De-Serialization
    /// </summary>
    internal static class JsonSerializerConfig
    {
        internal static readonly JsonSerializerOptions Default = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            IncludeFields = true
        };
    }
}
