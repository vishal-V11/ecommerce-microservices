using MassTransit;
using Ordering.Application.Abstractions;

namespace Ordering.Infrastructure.Messaging
{
    public sealed class EventPublisher : IEventPublisher
    {
        private readonly IPublishEndpoint _publishEndpoint;

        public EventPublisher(IPublishEndpoint publishEndpoint)
        {
            _publishEndpoint = publishEndpoint;
        }

        public async Task PublishAsync<T>(T @event, CancellationToken ct) where T : class
        {
            await _publishEndpoint.Publish(@event, ct);
        }
    }
}
