using Cart.Application.Common.DTOs;
using Cart.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cart.Application.Extensions
{
    public static class CartMappingExtensions
    {
        public static CartDto ToDto(this Domain.Entities.Cart cart)
        {
            return new CartDto(
                    cart.Items.Select(i => new CartItemDto
                    (
                        i.ProductId,
                        i.ProductName,
                        i.UnitPrice,
                        i.Quantity,
                        i.TotalPrice
                    )).ToList(),
                    cart.TotalPrice,
                    cart.LastModified
                );
        }
    }
}
