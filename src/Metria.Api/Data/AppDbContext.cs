using Metria.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace Metria.Api.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<Assessment> Assessments => Set<Assessment>();
    public DbSet<Goal> Goals => Set<Goal>();
    public DbSet<Subscription> Subscriptions => Set<Subscription>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Configure PostgreSQL to handle DateTime as UTC
        AppContext.SetSwitch("Npgsql.EnableLegacyTimestampBehavior", true);
        
        modelBuilder.Entity<User>(e =>
        {
            e.ToTable("users");
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(120).IsRequired();
            e.Property(x => x.Email).HasMaxLength(200).IsRequired();
            e.HasIndex(x => x.Email).IsUnique();
            e.Property(x => x.PasswordHash).HasMaxLength(256).IsRequired();
            e.Property(x => x.BirthDate).HasColumnType("date").IsRequired(false);
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
            e.Property(x => x.Period).IsRequired().HasConversion<string>();
            e.Property(x => x.StartDate).IsRequired();
            e.Property(x => x.EndDate).IsRequired();
            e.Property(x => x.Category).HasMaxLength(100).IsRequired(false);
            e.Property(x => x.CreatedAtUtc).IsRequired();
            e.Property(x => x.UpdatedAtUtc).IsRequired();
            e.Property(x => x.IsActive).IsRequired().HasDefaultValue(true);
            e.Property(x => x.UpdatedBy).HasMaxLength(200).IsRequired(false);
            e.HasOne(x => x.User)
             .WithMany()
             .HasForeignKey(x => x.UserId)
             .OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => new { x.UserId, x.Period, x.StartDate, x.EndDate });
            e.HasIndex(x => new { x.UserId, x.IsActive });
        });

        modelBuilder.Entity<Subscription>(e =>
        {
            e.ToTable("subscriptions");
            e.HasKey(x => x.Id);
            e.Property(x => x.Provider).HasMaxLength(50).IsRequired();
            e.Property(x => x.ProviderCustomerId).HasMaxLength(200).IsRequired(false);
            e.Property(x => x.ProviderSubscriptionId).HasMaxLength(200).IsRequired(false);
            e.Property(x => x.ProviderPriceId).HasMaxLength(200).IsRequired(false);
            e.Property(x => x.Plan).HasConversion<string>().IsRequired();
            e.Property(x => x.Status).HasConversion<string>().IsRequired();
            e.Property(x => x.CurrentPeriodStartUtc).IsRequired();
            e.Property(x => x.CurrentPeriodEndUtc).IsRequired();
            e.Property(x => x.CreatedAtUtc).IsRequired();
            e.Property(x => x.UpdatedAtUtc).IsRequired();
            e.HasOne(x => x.User)
             .WithMany()
             .HasForeignKey(x => x.UserId)
             .OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => x.UserId);
            e.HasIndex(x => new { x.UserId, x.Status, x.CurrentPeriodEndUtc });
            // Constraint única removida para permitir múltiplas assinaturas durante testes e processamento de webhook
            // e.HasIndex(x => x.UserId)
            //  .HasFilter("(\"Status\" IN ('Active','Trialing'))")
            //  .IsUnique()
            //  .HasDatabaseName("ux_subscriptions_user_active");
        });

    }
}
