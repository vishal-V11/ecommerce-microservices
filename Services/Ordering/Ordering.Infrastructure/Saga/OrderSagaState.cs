using MassTransit;
using Shared.Messaging.Contracts;
using Shared.Messaging.Enums;

namespace Ordering.Infrastructure.Saga
{
    public class OrderSagaState : SagaStateMachineInstance
    {
        public Guid CorrelationId { get; set; }
        public Guid OrderId { get; set; }
        public string UserId { get; set; } = default!;
        public string CurrentState { get; set; } = default!;
        public decimal TotalAmount { get; set; }
        public PaymentMethod PaymentMethod { get; set; }
        public IReadOnlyList<OrderItemContract> Items { get; set; } = [];
        public DateTimeOffset CreatedAt { get; set; }
        public byte[] RowVersion { get; set; } = default!;
    }
}
