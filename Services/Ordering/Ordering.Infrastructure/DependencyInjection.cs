using MassTransit;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Ordering.Application.Abstractions;
using Ordering.Infrastructure.Messaging;
using Ordering.Infrastructure.Persistence;
using Ordering.Infrastructure.Persistence.Repositories;
using Ordering.Infrastructure.Saga;
using Ordering.Infrastructure.Settings;
using Shared.Messaging.Constants;
using Shared.Messaging.Events.Order;
using Shared.Messaging.Events.Payment;
using Shared.Messaging.Events.Stock;

namespace Ordering.Infrastructure
{
    public static class DependencyInjection
    {
        public static IServiceCollection AddInfrastructure(this IServiceCollection services,DatabaseOptions dbOptions, KafkaOptions kafkaOptions)
        {
            services.AddDbContext<OrderDbContext>(options =>
                 options.UseNpgsql(dbOptions.Postgres).UseSnakeCaseNamingConvention());

            services.AddScoped<IOrderRepository, OrderRepository>();

            services.AddScoped<IEventPublisher, EventPublisher>();

            services.AddMassTransit(x =>
            {
                x.AddSagaStateMachine<OrderSaga, OrderSagaState>()
                 .EntityFrameworkRepository(r =>
                 {
                     r.ConcurrencyMode = ConcurrencyMode.Optimistic;
                     r.AddDbContext<DbContext, OrderDbContext>((service,options) =>
                         options.UseNpgsql(dbOptions.Postgres)
                                .UseSnakeCaseNamingConvention());
                 });

                x.UsingInMemory();

                x.AddRider(rider =>
                {
                    rider.AddSaga<OrderSagaState>();

                    rider.UsingKafka((ctx, k) =>
                    {
                        k.Host(kafkaOptions.BootstrapServers);

                        // Bootstraps Saga instance when a new order is placed
                        k.TopicEndpoint<OrderCreatedEvent>(
                            KafkaTopics.OrderCreated, KafkaGroups.OrderService, e =>
                            {
                                e.ConfigureSaga<OrderSagaState>(ctx);
                            });

                        // Inventory successfully reserved stock — proceed to payment
                        k.TopicEndpoint<StockLockedEvent>(
                            KafkaTopics.StockLocked, KafkaGroups.OrderService, e =>
                            {
                                e.ConfigureSaga<OrderSagaState>(ctx);
                            });

                        // Inventory failed to reserve stock — cancel order
                        k.TopicEndpoint<StockLockFailedEvent>(
                            KafkaTopics.StockLockFailed, KafkaGroups.OrderService, e =>
                            {
                                e.ConfigureSaga<OrderSagaState>(ctx);
                            });

                        // Payment succeeded — confirm stock, clear cart, notify user
                        k.TopicEndpoint<PaymentSucceededEvent>(
                            KafkaTopics.PaymentSucceeded, KafkaGroups.OrderService, e =>
                            {
                                e.ConfigureSaga<OrderSagaState>(ctx);
                            });

                        // Payment failed — release stock, cancel order, notify user
                        k.TopicEndpoint<PaymentFailedEvent>(
                            KafkaTopics.PaymentFailed, KafkaGroups.OrderService, e =>
                            {
                                e.ConfigureSaga<OrderSagaState>(ctx);
                            });
                    });
                });
            });


            return services;
        }
    }
}
