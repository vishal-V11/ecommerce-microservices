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
            string payload,
            CancellationToken cancellationToken = default
        );
    }
}
