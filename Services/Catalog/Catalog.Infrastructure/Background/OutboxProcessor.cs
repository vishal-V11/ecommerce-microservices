using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Catalog.Infrastructure.Background
{
    public class OutboxProcessor : BackgroundService
    {
        private readonly ILogger<OutboxProcessor> _logger;
        public OutboxProcessor(ILogger<OutboxProcessor> logger)
        {
            _logger = logger;     
        }
        protected async override Task ExecuteAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                _logger.LogInformation("Outbox pattern background service inititated");

                //Perform background task

                return;

            }
        }
    }
}
