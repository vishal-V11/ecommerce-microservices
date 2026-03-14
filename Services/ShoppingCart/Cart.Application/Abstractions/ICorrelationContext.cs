using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cart.Application.Abstractions
{
    public interface ICorrelationContext
    {
        string CorrelationId { get; }
    }
}
