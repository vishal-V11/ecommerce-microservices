using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Catalog.Application.Abstractions
{
    public interface IIntegrationEventPublisher
    {
        Task PublishAsync(
            string topic,
            string key,
            string payload,
            IDictionary<string, string>? headers = null,
            CancellationToken cancellationToken = default
        );
    }
}
