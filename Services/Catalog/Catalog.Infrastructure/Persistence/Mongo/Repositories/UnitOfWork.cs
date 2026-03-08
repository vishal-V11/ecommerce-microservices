using Catalog.Application.Abstractions;
using Catalog.Infrastructure.Persistence.Mongo;

namespace Catalog.Infrastructure.Persistence.Repositories
{
    public class UnitOfWork : IUnitOfWork
    {
        private readonly MongoContext _context;
        private readonly MongoSessionAccessor _sessionAccessor;
        public UnitOfWork(MongoContext context, MongoSessionAccessor sessionAccessor)
        {
            _context = context;
            _sessionAccessor = sessionAccessor;
        }

        public async Task ExecuteAsync(Func<CancellationToken, Task> action, CancellationToken ct)
        {
            using var session = await _context.Client.StartSessionAsync(cancellationToken: ct);

            _sessionAccessor.Session = session;

            session.StartTransaction();

            try
            {
                await action(ct);

                await session.CommitTransactionAsync();
            }
            catch
            {
                await session.AbortTransactionAsync();
                throw;
            }
            finally
            {
                _sessionAccessor.Session = null;
            }


        }
    }
}
