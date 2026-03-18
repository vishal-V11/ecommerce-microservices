using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;

namespace Ordering.Infrastructure.Persistence
{
    public class OrderDbContextFactory : IDesignTimeDbContextFactory<OrderDbContext>
    {
        public OrderDbContext CreateDbContext(string[] args)
        {
            // Reads from environment variable in CI/CD
            // Reads from appsettings.json locally
            var configuration = new ConfigurationBuilder()
                .SetBasePath(Path.Combine(Directory.GetCurrentDirectory(), "../Ordering.API"))
                .AddJsonFile("appsettings.json", optional: true)
                .AddJsonFile("appsettings.Development.json", optional: true)
                //.AddEnvironmentVariables() // CI/CD injects connection string here
                .Build();

            var options = new DbContextOptionsBuilder<OrderDbContext>()
                .UseNpgsql(configuration.GetConnectionString("Postgres"))
                .UseSnakeCaseNamingConvention()
                .Options;

            return new OrderDbContext(options);
        }
    }
}
