using Metria.Api.Models;

namespace Metria.Api.Services;

public interface ISubscriptionService
{
    Task<(bool active, SubscriptionPlan? plan, DateTime? renewsAtUtc)> GetStatusAsync(Guid userId, CancellationToken ct = default);
    Task UpsertAsync(Guid userId, SubscriptionPlan plan, SubscriptionStatus status, DateTime currentStart, DateTime currentEnd, string? providerCustomerId, string? providerSubscriptionId, string? providerPriceId, CancellationToken ct = default);
}
