using Metria.Api.Data;
using Metria.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace Metria.Api.Repositories;

public class SubscriptionRepository(AppDbContext db) : ISubscriptionRepository
{
    public async Task<Subscription?> GetActiveAsync(Guid userId, CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        return await db.Subscriptions.AsNoTracking()
            .Where(s => s.UserId == userId
                     && (s.Status == SubscriptionStatus.Active || s.Status == SubscriptionStatus.Trialing)
                     && s.CurrentPeriodEndUtc > now)
            .OrderByDescending(s => s.CurrentPeriodEndUtc)
            .FirstOrDefaultAsync(ct);
    }

    public async Task AddAsync(Subscription sub, CancellationToken ct = default)
    {
        await db.Subscriptions.AddAsync(sub, ct);
    }

    public Task UpdateAsync(Subscription sub, CancellationToken ct = default)
    {
        db.Subscriptions.Update(sub);
        return Task.CompletedTask;
    }

    public Task SaveChangesAsync(CancellationToken ct = default) => db.SaveChangesAsync(ct);
}

