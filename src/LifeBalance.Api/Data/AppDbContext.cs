using LifeBalance.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace LifeBalance.Api.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<Assessment> Assessments => Set<Assessment>();

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
    }
}
