using LifeBalance.Api.Models;
using LifeBalance.Api.Repositories;

namespace LifeBalance.Api.Services;

public class SubscriptionService(ISubscriptionRepository repo)
    : ISubscriptionService
{
    public async Task<(bool active, SubscriptionPlan? plan, DateTime? renewsAtUtc)> GetStatusAsync(Guid userId, CancellationToken ct = default)
    {
        var sub = await repo.GetActiveAsync(userId, ct);
        return sub is null
            ? (false, null, null)
            : (true, sub.Plan, sub.CurrentPeriodEndUtc);
    }

    public async Task UpsertAsync(
        Guid userId,
        SubscriptionPlan plan,
        SubscriptionStatus status,
        DateTime currentStart,
        DateTime currentEnd,
        string? providerCustomerId,
        string? providerSubscriptionId,
        string? providerPriceId,
        CancellationToken ct = default)
    {
        var existing = await repo.GetActiveAsync(userId, ct);
        if (existing is null)
        {
            var sub = new Subscription
            {
                UserId = userId,
                Plan = plan,
                Status = status,
                StartedAtUtc = status == SubscriptionStatus.Active || status == SubscriptionStatus.Trialing ? DateTime.UtcNow : null,
                CurrentPeriodStartUtc = currentStart,
                CurrentPeriodEndUtc = currentEnd,
                ProviderCustomerId = providerCustomerId,
                ProviderSubscriptionId = providerSubscriptionId,
                ProviderPriceId = providerPriceId,
                CreatedAtUtc = DateTime.UtcNow,
                UpdatedAtUtc = DateTime.UtcNow
            };
            await repo.AddAsync(sub, ct);
        }
        else
        {
            existing.Plan = plan;
            existing.Status = status;
            existing.CurrentPeriodStartUtc = currentStart;
            existing.CurrentPeriodEndUtc = currentEnd;
            existing.ProviderCustomerId = providerCustomerId ?? existing.ProviderCustomerId;
            existing.ProviderSubscriptionId = providerSubscriptionId ?? existing.ProviderSubscriptionId;
            existing.ProviderPriceId = providerPriceId ?? existing.ProviderPriceId;
            existing.UpdatedAtUtc = DateTime.UtcNow;
            await repo.UpdateAsync(existing, ct);
        }
        await repo.SaveChangesAsync(ct);
    }
}
