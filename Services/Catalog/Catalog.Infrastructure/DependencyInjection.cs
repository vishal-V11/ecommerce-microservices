using Catalog.Application.Abstractions;
using Catalog.Infrastructure.Background;
using Catalog.Infrastructure.Persistence.Mongo;
using Catalog.Infrastructure.Persistence.Mongo.DbSeeder;
using Catalog.Infrastructure.Persistence.Mongo.Repositories;
using Catalog.Infrastructure.Persistence.Repositories;
using Catalog.Infrastructure.Services;
using Catalog.Infrastructure.Settings;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
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
            services.AddScoped<IProductRepository, ProductRepository>();
            services.AddScoped<IOutboxRepository, OutboxRepository>();

            // Register the background service
            services.AddHostedService<OutboxProcessor>();

            return services;
        }
     
    }
}
