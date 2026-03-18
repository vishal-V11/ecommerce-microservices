namespace Shared.Messaging.Contracts
{
    public sealed record OrderItemContract(

        Guid ProductId,
        int Quantity
    );

}
