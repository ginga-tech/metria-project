namespace LifeBalance.Api.Models;

public class User
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty; // stored lower-case
    public string PasswordHash { get; set; } = string.Empty; // "oauth_google" for SSO
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    public ICollection<Assessment> Assessments { get; set; } = new List<Assessment>();
}
