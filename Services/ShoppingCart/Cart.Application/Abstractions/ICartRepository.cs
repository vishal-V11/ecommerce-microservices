namespace Cart.Application.Abstractions
{
    public interface ICartRepository
    {
        Task<Domain.Entities.Cart?> GetCartAsync(string userId, CancellationToken ct = default);
        Task SaveCartAsync(Domain.Entities.Cart cart,CancellationToken ct = default);
        Task DeleteCartAsync(string userId, CancellationToken ct = default);
    }
}
