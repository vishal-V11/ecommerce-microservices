using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cart.Domain.Exceptions
{
    public class CartItemNotFoundException : Exception
    {
        
        public CartItemNotFoundException(Guid ProductId)
            : base($"Product '{ProductId}' was not found in the cart")
        {

        }
    }
}
