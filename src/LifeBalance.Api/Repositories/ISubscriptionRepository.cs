using LifeBalance.Api.Models;

namespace LifeBalance.Api.Repositories;

public interface ISubscriptionRepository
{
    Task<Subscription?> GetActiveAsync(Guid userId, CancellationToken ct = default);
    Task AddAsync(Subscription sub, CancellationToken ct = default);
    Task UpdateAsync(Subscription sub, CancellationToken ct = default);
    Task SaveChangesAsync(CancellationToken ct = default);
}

