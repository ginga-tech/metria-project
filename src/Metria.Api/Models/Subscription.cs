using System.ComponentModel.DataAnnotations;

namespace Metria.Api.Models;

public enum SubscriptionStatus
{
    Incomplete,
    IncompleteExpired,
    Trialing,
    Active,
    PastDue,
    Canceled,
    Unpaid
}

public enum SubscriptionPlan
{
    Monthly,
    Annual
}

public class Subscription
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public Guid UserId { get; set; }

    public string Provider { get; set; } = "stripe";
    // Generic provider references (e.g., Stripe/MercadoPago/etc)
    public string? ProviderCustomerId { get; set; }
    public string? ProviderSubscriptionId { get; set; }
    public string? ProviderPriceId { get; set; }

    [Required]
    public SubscriptionPlan Plan { get; set; }

    [Required]
    public SubscriptionStatus Status { get; set; } = SubscriptionStatus.Incomplete;

    public DateTime? StartedAtUtc { get; set; }
    public DateTime CurrentPeriodStartUtc { get; set; }
    public DateTime CurrentPeriodEndUtc { get; set; }
    public DateTime? CanceledAtUtc { get; set; }

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;

    public User? User { get; set; }
}
