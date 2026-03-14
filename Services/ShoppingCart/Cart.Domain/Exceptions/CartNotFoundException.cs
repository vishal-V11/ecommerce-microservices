using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cart.Domain.Exceptions
{
    public class CartNotFoundException : Exception
    {
        public CartNotFoundException(string userId)
            : base($"Cart for user '{userId}' was not found.") 
        { 
        
        }
    }
}
