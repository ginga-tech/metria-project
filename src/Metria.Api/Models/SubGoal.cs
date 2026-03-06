using System.ComponentModel.DataAnnotations;

namespace Metria.Api.Models;

public class SubGoal
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public Guid GoalId { get; set; }

    [Required]
    [MaxLength(300)]
    public string Text { get; set; } = string.Empty;

    public bool Done { get; set; } = false;

    [Required]
    public DateTime StartDate { get; set; }

    [Required]
    public DateTime EndDate { get; set; }

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;

    public bool IsActive { get; set; } = true;

    [MaxLength(200)]
    public string? UpdatedBy { get; set; }

    public Goal Goal { get; set; } = null!;
}
