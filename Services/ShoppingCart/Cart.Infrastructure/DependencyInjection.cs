using Cart.Application.Abstractions;
using Cart.Infrastructure.Mesagging;
using Cart.Infrastructure.Repositories;
using Cart.Infrastructure.Settings;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace Cart.Infrastructure
{
    public static class DependencyInjection
    {
        public static IServiceCollection AddInfraStructure(this IServiceCollection services)
        {
            //Redis Configuration
            services.AddSingleton<IConnectionMultiplexer>(sp =>
            {
                var settings = sp.GetRequiredService<IOptions<RedisSettings>>().Value;
                return ConnectionMultiplexer.Connect(settings.ConnectionString);
            });

            services.AddSingleton<KafkaFactory>();
            services.AddScoped<ICartRepository, CartRepository>();
            return services;
        }
    }
}
