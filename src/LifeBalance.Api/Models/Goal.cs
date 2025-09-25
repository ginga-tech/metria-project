using System.ComponentModel.DataAnnotations;

namespace LifeBalance.Api.Models;

public class Goal
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();
    
    [Required]
    public Guid UserId { get; set; }
    
    [Required]
    [MaxLength(500)]
    public string Text { get; set; } = string.Empty;
    
    public bool Done { get; set; } = false;
    
    [Required]
    [MaxLength(10)]
    public string WeekId { get; set; } = string.Empty; // Format: "2024-42"
    
    public DateTime CreatedAtUtc { get; set; }
    
    public DateTime UpdatedAtUtc { get; set; }
    
    // Navigation property
    public User User { get; set; } = null!;
}
