namespace Metria.Api.Models;

public class Assessment
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public User? User { get; set; }

    public string ScoresJson { get; set; } = "{}"; // serialized dictionary
    public double Average { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
}
