using LifeBalance.API.Models.Enums;
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
    public GoalPeriod Period { get; set; } = GoalPeriod.Weekly;
    
    [Required]
    public DateTime StartDate { get; set; }
    
    [Required]
    public DateTime EndDate { get; set; }
    
    [MaxLength(100)]
    public string? Category { get; set; }
    
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    
    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;
    
    // Navigation property
    public User User { get; set; } = null!;
}
