using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Catalog.Application.Common.Security
{
    public sealed class CurrentUser
    {
        public string UserId { get; init; } = default!;
        public string? Email { get; init; }
        public IReadOnlyCollection<string> Roles { get; init; } = Array.Empty<string>();
        public bool IsAuthenticated { get; init; }
    }
}
