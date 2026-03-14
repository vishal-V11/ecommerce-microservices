using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cart.Application.Common.DTOs
{
    public record CartDto
    (
        List<CartItemDto> Items,
        decimal TotalPrice,
        DateTimeOffset LastModified
    );


    public record CartItemDto
    (
        Guid ProductId,
        string ProductName,
        decimal UnitPrice,
        int Quantity,
        decimal TotalPrice
    );

    public record AddItemRequest
    (
        Guid ProductId,
        string ProductName,
        decimal UnitPrice
    );

    public record IncrementItemRequest(Guid ProductId,int Quantity);
    public record DecrementItemRequest(Guid ProductId,int Quantity);


}
