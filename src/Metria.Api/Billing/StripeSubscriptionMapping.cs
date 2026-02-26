using Metria.Api.Models;
using Microsoft.Extensions.Configuration;
using StripeSubscription = Stripe.Subscription;

namespace Metria.Api.Billing;

public static class StripeSubscriptionMapping
{
    public static SubscriptionPlan MapPlan(IConfiguration cfg, string? priceId, string? interval)
    {
        var monthlyPriceId = Environment.GetEnvironmentVariable("STRIPE_MONTHLY_PRICE_ID") ?? cfg["Stripe:MonthlyPriceId"];
        var annualPriceId = Environment.GetEnvironmentVariable("STRIPE_ANNUAL_PRICE_ID") ?? cfg["Stripe:AnnualPriceId"];

        if (!string.IsNullOrWhiteSpace(priceId))
        {
            if (!string.IsNullOrWhiteSpace(monthlyPriceId) && priceId == monthlyPriceId) return SubscriptionPlan.Monthly;
            if (!string.IsNullOrWhiteSpace(annualPriceId) && priceId == annualPriceId) return SubscriptionPlan.Annual;
        }

        if (!string.IsNullOrWhiteSpace(interval))
        {
            if (string.Equals(interval, "month", StringComparison.OrdinalIgnoreCase)) return SubscriptionPlan.Monthly;
            if (string.Equals(interval, "year", StringComparison.OrdinalIgnoreCase)) return SubscriptionPlan.Annual;
        }

        return SubscriptionPlan.Monthly;
    }

    public static SubscriptionStatus MapStatus(string? status) => (status ?? string.Empty).ToLowerInvariant() switch
    {
        "incomplete" => SubscriptionStatus.Incomplete,
        "incomplete_expired" => SubscriptionStatus.IncompleteExpired,
        "trialing" => SubscriptionStatus.Trialing,
        "active" => SubscriptionStatus.Active,
        "past_due" => SubscriptionStatus.PastDue,
        "canceled" => SubscriptionStatus.Canceled,
        "unpaid" => SubscriptionStatus.Unpaid,
        _ => SubscriptionStatus.Incomplete
    };

    public static DateTime? GetStripeDate(StripeSubscription subscription, string propertyName)
    {
        var property = subscription.GetType().GetProperty(propertyName);
        var value = property?.GetValue(subscription);

        if (value is DateTime dt) return dt.ToUniversalTime();
        if (value is long unixSeconds) return DateTimeOffset.FromUnixTimeSeconds(unixSeconds).UtcDateTime;

        return null;
    }
}
