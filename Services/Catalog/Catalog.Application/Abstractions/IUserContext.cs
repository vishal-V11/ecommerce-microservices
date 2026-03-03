using Catalog.Application.Common.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Catalog.Application.Abstractions
{
    public interface IUserContext
    {
        CurrentUser User { get; }
    }
}
