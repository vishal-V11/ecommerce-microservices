using Catalog.Application.Abstractions;
using Catalog.Infrastructure.Background;
using Catalog.Infrastructure.Messaging;
using Catalog.Infrastructure.Messaging.Producers;
using Catalog.Infrastructure.Persistence.Mongo;
using Catalog.Infrastructure.Persistence.Mongo.DbSeeder;
using Catalog.Infrastructure.Persistence.Mongo.Repositories;
using Catalog.Infrastructure.Persistence.Repositories;
using Catalog.Infrastructure.Services;
using Catalog.Infrastructure.Settings;
using Confluent.Kafka;
using DnsClient.Internal;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Polly;
using StackExchange.Redis;

namespace Catalog.Infrastructure
{
    public static class DependencyInjection
    {
        public static IServiceCollection AddInfrastructure(this IServiceCollection services)
        {
            //Redis Configuration
            services.AddSingleton<IConnectionMultiplexer>(sp =>
            {
                var settings = sp.GetRequiredService<IOptions<RedisSettings>>().Value;
                return ConnectionMultiplexer.Connect(settings.ConnectionString);
            });
            services.AddScoped<ICacheService, RedisCacheService>();

            services.AddSingleton<MongoContext>();
            services.AddScoped<MongoSessionAccessor>();

            services.AddScoped<DatabaseSeeder>();
            services.AddScoped<IUnitOfWork, UnitOfWork>();
            services.AddScoped<IBrandRepository, BrandRepository>();
            services.AddScoped<ICategoryRepository, CategoryRepository>();
            services.AddScoped<IProductRepository, ProductRepository>();
            services.AddScoped<IProductReadRepository, ProductReadRepository>();
            services.AddScoped<IOutboxRepository, OutboxRepository>();

            // DI handles the factory itself
            services.AddSingleton<KafkaFactory>();
            services.AddScoped<IIntegrationEventPublisher, KafkaIntegrationEventPublisher>();

            //Polly Resiliance Pipeline
            services.AddResiliencePipeline("kafka-publish-pipeline", (pipelineBuilder, context) =>
            {
                var logger = context.ServiceProvider
                    .GetRequiredService<ILogger<OutboxProcessor>>();

                pipelineBuilder
                    .AddRetry(new Polly.Retry.RetryStrategyOptions
                    {
                        // Max 3 retries (4 total attempts)
                        MaxRetryAttempts = 3,

                        // Start at 50ms, double each attempt
                        Delay = TimeSpan.FromMilliseconds(50),
                        BackoffType = DelayBackoffType.Exponential,

                        // Spread retries randomly to avoid retry storms
                        UseJitter = true,

                        OnRetry = args =>
                        {
                            logger.LogWarning("Attempt {Attempt}/{MaxAttempts}. Waiting {Delay}ms before retry"
                                ,args.AttemptNumber+1
                                ,3
                                ,args.RetryDelay.TotalMilliseconds);

                            return ValueTask.CompletedTask;
                        }

                    });
            });
            

            // Register the background service
            services.AddHostedService<OutboxProcessor>();

            return services;
        }
     
    }
}
