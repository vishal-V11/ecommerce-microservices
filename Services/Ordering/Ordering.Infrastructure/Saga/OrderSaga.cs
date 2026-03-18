using MassTransit;
using Ordering.Application.Abstractions;
using Shared.Messaging.Events.Cart;
using Shared.Messaging.Events.Notification;
using Shared.Messaging.Events.Order;
using Shared.Messaging.Events.Payment;
using Shared.Messaging.Events.Stock;

namespace Ordering.Infrastructure.Saga
{
    /// <summary>
    /// Orchestrates the entire order fulfillment flow using a MassTransit state machine.
    /// Acts as the central coordinator — listens for events from Inventory and Payment
    /// services and publishes commands in response. The Saga never performs business logic
    /// itself; it only transitions state and publishes the next event in the chain.
    /// <br/>
    /// Flow:
    /// OrderCreated → StockLockRequested <br/>
    ///     → StockLocked → PaymentProcessRequested
    ///         → PaymentSucceeded → StockConfirm + CartClear + Notify → Completed
    ///         → PaymentFailed → StockRelease + Notify → Cancelled <br/>
    ///     → StockLockFailed → Notify → Cancelled
    /// </summary>
    public sealed class OrderSaga : MassTransitStateMachine<OrderSagaState>
    {
        private readonly IOrderRepository _orderRepository;

        /// <summary>
        /// Saga is waiting for Inventory Service to respond with
        /// StockLockedEvent or StockLockFailedEvent.
        /// </summary>
        public State WaitingForStockLock { get; private set; } = default!;

        /// <summary>
        /// Stock has been successfully locked. Saga is waiting for
        /// Payment Service to respond with PaymentSucceededEvent or PaymentFailedEvent.
        /// </summary>
        public State WaitingForPayment { get; private set; } = default!;

        /// <summary>
        /// Terminal state — order fulfilled successfully.
        /// Stock confirmed, cart cleared, user notified.
        /// </summary>
        public State Completed { get; private set; } = default!;

        /// <summary>
        /// Terminal state — order cancelled.
        /// Either stock lock failed or payment failed.
        /// Stock released if applicable, user notified.
        /// </summary>
        public State Cancelled { get; private set; } = default!;

        /// <summary>
        /// Bootstraps the Saga. Published by PlaceOrderHandler after
        /// persisting the Order. Creates a new Saga instance in Postgres.
        /// </summary>
        public Event<OrderCreatedEvent> OrderCreated { get; private set; } = default!;

        /// <summary>
        /// Published by Inventory Service after successfully reserving
        /// stock for all items in the order atomically.
        /// </summary>
        public Event<StockLockedEvent> StockLocked { get; private set; } = default!;

        /// <summary>
        /// Published by Inventory Service when stock reservation fails
        /// due to insufficient quantity for one or more items.
        /// </summary>
        public Event<StockLockFailedEvent> StockLockFailed { get; private set; } = default!;

        /// <summary>
        /// Published by Payment Service after successfully processing payment.
        /// For MVP this is always published immediately by the stub consumer.
        /// </summary>
        public Event<PaymentSucceededEvent> PaymentSucceeded { get; private set; } = default!;

        /// <summary>
        /// Published by Payment Service when payment processing fails.
        /// Triggers stock release and order cancellation.
        /// </summary>
        public Event<PaymentFailedEvent> PaymentFailed { get; private set; } = default!;

        public OrderSaga(IOrderRepository orderRepository)
        {
            _orderRepository = orderRepository;

            // Tells MassTransit which property on OrderSagaState holds the current state string
            InstanceState(x => x.CurrentState);

            // All events correlate by CorrelationId = OrderId
            // MassTransit uses this to find the correct Saga instance row in database
            Event(() => OrderCreated, e => e.CorrelateById(m => m.Message.CorrelationId));
            Event(() => StockLocked, e => e.CorrelateById(m => m.Message.CorrelationId));
            Event(() => StockLockFailed, e => e.CorrelateById(m => m.Message.CorrelationId));
            Event(() => PaymentSucceeded, e => e.CorrelateById(m => m.Message.CorrelationId));
            Event(() => PaymentFailed, e => e.CorrelateById(m => m.Message.CorrelationId));

            // -------------------------------------------------------------------------
            // Step 1 — Order Created → Lock Stock
            // Triggered by PlaceOrderHandler. Bootstraps the Saga instance,
            // stores order data into Saga state for use in downstream steps,
            // and immediately requests stock lock from Inventory Service.
            // -------------------------------------------------------------------------
            Initially(
                When(OrderCreated)
                .Then(ctx =>
                {
                    // Populate Saga state from the event so downstream steps
                    // never need to query the Order table mid-flow
                    ctx.Saga.OrderId = ctx.Message.OrderId;
                    ctx.Saga.UserId = ctx.Message.UserId;
                    ctx.Saga.TotalAmount = ctx.Message.TotalAmount;
                    ctx.Saga.PaymentMethod = ctx.Message.PaymentMethod;
                    ctx.Saga.Items = ctx.Message.Items;
                    ctx.Saga.CreatedAt = DateTimeOffset.UtcNow;
                })
                // Publish a single event with all items — Inventory Service
                // locks stock atomically in one transaction
                .Publish(ctx => new StockLockRequestedEvent(
                    CorrelationId: ctx.Saga.CorrelationId,
                    Items: ctx.Saga.Items,
                    UserId: ctx.Saga.UserId,
                    OccurredOn: DateTimeOffset.UtcNow))
                .TransitionTo(WaitingForStockLock)
                );

            During(WaitingForStockLock,

                // -------------------------------------------------------------------------
                // Step 2 — Stock Locked → Request Payment
                // Inventory successfully reserved stock for all items.
                // Saga moves forward and hands off to Payment Service.
                // -------------------------------------------------------------------------

                When(StockLocked)
                    .Publish(ctx => new PaymentProcessRequestedEvent(
                        CorrelationId: ctx.Saga.CorrelationId,
                        UserId: ctx.Saga.UserId,
                        Amount: ctx.Saga.TotalAmount,
                        PaymentMethod: ctx.Saga.PaymentMethod,
                        OccurredOn: DateTimeOffset.UtcNow
                    ))
                    .TransitionTo(WaitingForPayment),

                // -------------------------------------------------------------------------
                // Step 4 — Stock Lock Failed → Cancel Order
                // Inventory couldn't reserve stock — insufficient quantity.
                // Order is cancelled and user is notified. No payment attempted.
                // -------------------------------------------------------------------------
                When(StockLockFailed)
                    .ThenAsync(async ctx =>
                    {
                        // Cancel the Order aggregate in Postgres
                        var order = await orderRepository.GetByIdAsync(ctx.Saga.OrderId, CancellationToken.None);
                        order!.CancelStatus();
                        await _orderRepository.SaveChangesAsync(CancellationToken.None);
                    })
                    .Publish(ctx => new SendNotificationEvent(
                      CorrelationId: ctx.Saga.CorrelationId,
                      UserId: ctx.Saga.UserId,
                      Message: $"Your order was cancelled. Reason: {ctx.Message.Reason}",
                      OccurredOn: DateTime.UtcNow))
                .TransitionTo(Cancelled)
                .Finalize());

            During(WaitingForPayment,

                // -------------------------------------------------------------------------
                // Step 3 (success) — Payment Succeeded → Confirm Stock + Clear Cart + Notify
                // Payment went through. Order is confirmed, stock reservation is converted
                // to an actual deduction, cart is cleared, user is notified.
                // -------------------------------------------------------------------------

                When(PaymentSucceeded)
                    .ThenAsync(async ctx =>
                    {
                        // Confirm the Order aggregate — transitions status to Confirmed
                        var order = await _orderRepository.GetByIdAsync(ctx.Saga.OrderId, CancellationToken.None);
                        order!.ConfirmStatus();
                        await _orderRepository.SaveChangesAsync(CancellationToken.None);
                    })

                    // Tells Inventory to convert ReservedQty into actual deduction
                    .Publish(ctx => new StockConfirmEvent(
                        CorrelationId: ctx.Saga.CorrelationId,
                        Items: ctx.Saga.Items,
                        OccurredOn: DateTime.UtcNow))
                    // Tells Cart Service to clear the user's cart
                    .Publish(ctx => new CartClearEvent(
                        CorrelationId: ctx.Saga.CorrelationId,
                        UserId: ctx.Saga.UserId,
                        OccurredOn: DateTime.UtcNow))
                    .Publish(ctx => new SendNotificationEvent(
                        CorrelationId: ctx.Saga.CorrelationId,
                        UserId: ctx.Saga.UserId,
                        Message: "Your order has been confirmed!",
                        OccurredOn: DateTime.UtcNow))
                    .TransitionTo(Completed)
                    .Finalize(),

                // -------------------------------------------------------------------------
                // Step 3 (failure) — Payment Failed → Release Stock + Cancel Order
                // Payment didn't go through. Stock reservation is released,
                // order is cancelled, user is notified.
                // -------------------------------------------------------------------------

                When(PaymentFailed)
                .ThenAsync(async ctx =>
                {
                    // Cancel the Order aggregate in Postgres
                    var order = await orderRepository.GetByIdAsync(ctx.Saga.OrderId, CancellationToken.None);
                    order!.CancelStatus();
                    await orderRepository.SaveChangesAsync(CancellationToken.None);
                })
                // Tells Inventory to release ReservedQty — actual stock untouched
                .Publish(ctx => new StockReleaseEvent(
                    CorrelationId: ctx.Saga.CorrelationId,
                    Items: ctx.Saga.Items,
                    OccurredOn: DateTime.UtcNow))
                .Publish(ctx => new SendNotificationEvent(
                    CorrelationId: ctx.Saga.CorrelationId,
                    UserId: ctx.Saga.UserId,
                    Message: $"Your order was cancelled. Reason: {ctx.Message.Reason}",
                    OccurredOn: DateTime.UtcNow))
                .TransitionTo(Cancelled)
                .Finalize());


            // Automatically removes the Saga instance row from Postgres
            // once it reaches a terminal state (Completed or Cancelled).
            // Keeps the saga_states table lean — historical data lives in the Orders table.
            SetCompletedWhenFinalized();

        }

    }
}
