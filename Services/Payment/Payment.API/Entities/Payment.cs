using Payment.API.Enums;
using Shared.Messaging.Enums;

namespace Payment.API.Entities
{
    public sealed class Payment
    {
        public Guid PaymentId { get; init; }
        public Guid CorrelationId { get; init; }
        public string UserId { get; init; }
        public decimal Amount { get; init; }
        public PaymentMethod PaymentMethod { get; init; }
        public PaymentStatus Status { get; set; }
        public string? FailureReason { get; set; }
        public DateTimeOffset CreatedAt { get; init; }
        public DateTimeOffset? ProcessedAt { get; set; }

        //Constructor for EF
        private Payment() { }

        public static Payment CreateSucceeded(Guid correlationId, string userId, decimal amount, PaymentMethod paymentMethod) =>
        new()
        {
            PaymentId = Guid.NewGuid(),
            CorrelationId = correlationId,
            UserId = userId,
            Amount = amount,
            PaymentMethod = paymentMethod,
            Status = PaymentStatus.Succeeded,
            CreatedAt = DateTimeOffset.UtcNow,
            ProcessedAt = DateTimeOffset.UtcNow
        };

        public static Payment CreateFailed(Guid correlationId, string userId, decimal amount, PaymentMethod paymentMethod, string failureReason) =>
            new()
            {
                PaymentId = Guid.NewGuid(),
                CorrelationId = correlationId,
                UserId = userId,
                Amount = amount,
                PaymentMethod = paymentMethod,
                Status = PaymentStatus.Failed,
                FailureReason = failureReason,
                CreatedAt = DateTimeOffset.UtcNow,
                ProcessedAt = DateTimeOffset.UtcNow
            };

    }
}
