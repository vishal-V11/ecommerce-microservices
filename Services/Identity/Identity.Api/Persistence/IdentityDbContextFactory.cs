using Identity.Api.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Identity.Api.Persistence
{
    public class IdentityDbContextFactory : IDesignTimeDbContextFactory<ApplicationDbContext>
    {
        public ApplicationDbContext CreateDbContext(string[] args)
        {
            var basePath = Directory.GetCurrentDirectory();
            // Reads from environment variable in CI/CD
            // Reads from appsettings.json locally
            var configuration = new ConfigurationBuilder()
                .SetBasePath(basePath)
                .AddJsonFile("appsettings.json", optional: true)
                .AddJsonFile("appsettings.Development.json", optional: true)
                //.AddEnvironmentVariables() // CI/CD injects connection string here
                .Build();

            var connectionString =
                configuration.GetConnectionString("identityDb")
                ?? "Host=localhost;Port=5432;Database=ecommerce_inventorydb;Username=postgres;Password=admin";


            var options = new DbContextOptionsBuilder<ApplicationDbContext>()
                .UseNpgsql(connectionString)
                .UseSnakeCaseNamingConvention()
                .Options;

            return new ApplicationDbContext(options);
        }
    }
}
