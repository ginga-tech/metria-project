using LifeBalance.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace LifeBalance.Api.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<Assessment> Assessments => Set<Assessment>();
    public DbSet<Goal> Goals => Set<Goal>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>(e =>
        {
            e.ToTable("users");
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(120).IsRequired();
            e.Property(x => x.Email).HasMaxLength(200).IsRequired();
            e.HasIndex(x => x.Email).IsUnique();
            e.Property(x => x.PasswordHash).HasMaxLength(256).IsRequired();
        });

        modelBuilder.Entity<Assessment>(e =>
        {
            e.ToTable("assessments");
            e.HasKey(x => x.Id);
            e.Property(x => x.ScoresJson).HasColumnType("text").IsRequired();
            e.Property(x => x.Average).IsRequired();
            e.Property(x => x.CreatedAtUtc).IsRequired();
            e.HasOne(x => x.User)
             .WithMany(u => u.Assessments)
             .HasForeignKey(x => x.UserId)
             .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<Goal>(e =>
        {
            e.ToTable("goals");
            e.HasKey(x => x.Id);
            e.Property(x => x.Text).HasMaxLength(500).IsRequired();
            e.Property(x => x.Done).IsRequired();
            e.Property(x => x.WeekId).HasMaxLength(10).IsRequired();
            e.Property(x => x.CreatedAtUtc).IsRequired();
            e.Property(x => x.UpdatedAtUtc).IsRequired();
            e.HasOne(x => x.User)
             .WithMany()
             .HasForeignKey(x => x.UserId)
             .OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => new { x.UserId, x.WeekId });
        });
    }
}
