using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Catalog.Application.Common.Outbox
{
    public sealed record OutboxMessage
    {
        public Guid EventId { get; init; }

        public string Topic { get; init; } = default!;

        public string Payload { get; init; } = default!;

        public string CorrelationId { get; init; } = default!;

        public DateTimeOffset OccurredOnUtc { get; init; }
    }
}
