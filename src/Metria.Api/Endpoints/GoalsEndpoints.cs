using Metria.Api.Auth;
using Metria.Api.Contracts;
using Metria.Api.Data;
using Metria.Api.Models;
using Metria.API.Models.Enums;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Globalization;
using System.Security.Claims;

namespace Metria.Api.Endpoints;

public static class GoalsEndpoints
{
    public static WebApplication MapGoalsEndpoints(this WebApplication app)
    {
        const string Tag = "Goals";
        var goals = app.MapGroup("/api/goals").WithTags(Tag);

        // Goals endpoints
        goals.MapPost("", async (ClaimsPrincipal user, CreateGoalDto dto, AppDbContext db) =>
        {
            try
            {
                
                var email = user.GetEmail();
                if (string.IsNullOrWhiteSpace(email)) 
                {
                    return Results.Unauthorized();
                }
        
                var u = await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Email == email);
                if (u is null) 
                {
                    return Results.Unauthorized();
                }
        
                if (string.IsNullOrWhiteSpace(dto.Text) || dto.Text.Length > 500)
                {
                    return Results.BadRequest("Texto da meta é obrigatório e deve ter no máximo 500 caracteres");
                }
        
                if (!Enum.IsDefined(typeof(GoalPeriod), dto.Period))
                {
                    return Results.BadRequest("Período da meta inválido");
                }
        
                if (dto.StartDate >= dto.EndDate)
                {
                    return Results.BadRequest("Data de início deve ser anterior à data de fim");
                }
        
        
                // Paywall enforcement: free plan allows up to 5 goals total
                var now = DateTime.UtcNow;
                var hasActive = await db.Subscriptions.AsNoTracking()
                    .AnyAsync(s => s.UserId == u.Id && (s.Status == SubscriptionStatus.Active || s.Status == SubscriptionStatus.Trialing) && s.CurrentPeriodEndUtc > now);
                if (!hasActive)
                {
                    var totalGoals = await db.Goals.AsNoTracking().CountAsync(g => g.UserId == u.Id && g.IsActive);
                    if (totalGoals >= 5)
                    {
                        return Results.StatusCode(402); // Payment Required
                    }
                }
        
                var goal = new Goal
                {
                    UserId = u.Id,
                    Text = dto.Text.Trim(),
                    Period = dto.Period,
                    StartDate = dto.StartDate.Kind == DateTimeKind.Utc ? dto.StartDate : 
                               dto.StartDate.Kind == DateTimeKind.Local ? dto.StartDate.ToUniversalTime() : 
                               DateTime.SpecifyKind(dto.StartDate, DateTimeKind.Utc),
                    EndDate = dto.EndDate.Kind == DateTimeKind.Utc ? dto.EndDate : 
                             dto.EndDate.Kind == DateTimeKind.Local ? dto.EndDate.ToUniversalTime() : 
                             DateTime.SpecifyKind(dto.EndDate, DateTimeKind.Utc),
                    Category = dto.Category?.Trim(),
                    Done = false,
                    CreatedAtUtc = DateTime.UtcNow,
                    UpdatedAtUtc = DateTime.UtcNow,
                    IsActive = true,
                    UpdatedBy = email
                };
        
                db.Goals.Add(goal);
                
                await db.SaveChangesAsync();
                
        
                return Results.Created($"/api/goals/{goal.Id}", new GoalDto(
                    goal.Id, goal.Text, goal.Done, goal.Period.ToString(), 
                    goal.StartDate.ToString("yyyy-MM-dd"), goal.EndDate.ToString("yyyy-MM-dd"),
                    goal.Category, goal.CreatedAtUtc.ToString("O")
                ));
            }
            catch (Exception ex)
            {
                return Results.BadRequest($"Erro interno: {ex.Message}");
            }
        }).RequireAuthorization();
        
        goals.MapGet("", async (ClaimsPrincipal user, [FromServices] AppDbContext db, string? period = null, string? startDate = null, string? endDate = null) =>
        {
            var email = user.GetEmail();
            if (string.IsNullOrWhiteSpace(email)) return Results.Unauthorized();
        
            var u = await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Email == email);
            if (u is null) return Results.Unauthorized();
        
            var query = db.Goals.AsNoTracking().Where(g => g.UserId == u.Id && g.IsActive);
        
            if (!string.IsNullOrWhiteSpace(period) && Enum.TryParse<GoalPeriod>(period, true, out var goalPeriod))
            {
                query = query.Where(g => g.Period == goalPeriod);
            }
        
                if (!string.IsNullOrWhiteSpace(startDate))
            {
                if (DateTimeOffset.TryParse(startDate, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var start))
                {
                    var startUtc = start.UtcDateTime;
                    query = query.Where(g => g.StartDate >= startUtc);
                }
                else if (DateTime.TryParseExact(startDate, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var sd))
                {
                    var sUtc = DateTime.SpecifyKind(sd, DateTimeKind.Utc);
                    query = query.Where(g => g.StartDate >= sUtc);
                }
            }
        
                if (!string.IsNullOrWhiteSpace(endDate))
            {
                if (DateTimeOffset.TryParse(endDate, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var end))
                {
                    var endUtc = end.UtcDateTime;
                    query = query.Where(g => g.EndDate <= endUtc);
                }
                else if (DateTime.TryParseExact(endDate, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var ed))
                {
                    var eUtc = DateTime.SpecifyKind(ed, DateTimeKind.Utc);
                    query = query.Where(g => g.EndDate <= eUtc);
                }
            }
        
            var goals = await query.OrderByDescending(g => g.CreatedAtUtc).ToListAsync();
        
            var goalDtos = goals.Select(g => new GoalDto(
                g.Id, g.Text, g.Done, g.Period.ToString(),
                g.StartDate.ToString("yyyy-MM-dd"), g.EndDate.ToString("yyyy-MM-dd"),
                g.Category, g.CreatedAtUtc.ToString("O")
            )).ToList();
        
            return Results.Ok(goalDtos);
        }).RequireAuthorization();
        
        goals.MapPut("/{id:guid}", async (ClaimsPrincipal user, Guid id, UpdateGoalDto dto, [FromServices] AppDbContext db) =>
        {
            var email = user.GetEmail();
            if (string.IsNullOrWhiteSpace(email)) return Results.Unauthorized();
        
            var u = await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Email == email);
            if (u is null) return Results.Unauthorized();
        
            var goal = await db.Goals.FirstOrDefaultAsync(g => g.Id == id && g.UserId == u.Id && g.IsActive);
            if (goal is null) return Results.NotFound();
        
            goal.Done = dto.Done;
            goal.UpdatedAtUtc = DateTime.UtcNow;
            goal.UpdatedBy = email;
        
            await db.SaveChangesAsync();
        
            return Results.Ok(new GoalDto(
                goal.Id, goal.Text, goal.Done, goal.Period.ToString(),
                goal.StartDate.ToString("yyyy-MM-dd"), goal.EndDate.ToString("yyyy-MM-dd"),
                goal.Category, goal.CreatedAtUtc.ToString("O")
            ));
        }).RequireAuthorization();
        
        goals.MapDelete("/{id:guid}", async (ClaimsPrincipal user, Guid id, [FromServices] AppDbContext db) =>
        {
            var email = user.GetEmail();
            if (string.IsNullOrWhiteSpace(email)) return Results.Unauthorized();
        
            var u = await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Email == email);
            if (u is null) return Results.Unauthorized();
        
            var goal = await db.Goals.FirstOrDefaultAsync(g => g.Id == id && g.UserId == u.Id && g.IsActive);
            if (goal is null) return Results.NotFound();
        
            // Debug: Log valores antes da atualização
        
            // Soft delete: marca como inativo em vez de remover fisicamente
            goal.IsActive = false;
            goal.UpdatedAtUtc = DateTime.UtcNow;
            goal.UpdatedBy = email;
        
            // Debug: Log valores após a atualização (antes de salvar)
        
            // Marcar explicitamente o campo como modificado
            db.Entry(goal).Property(x => x.IsActive).IsModified = true;
            db.Entry(goal).Property(x => x.UpdatedAtUtc).IsModified = true;
            db.Entry(goal).Property(x => x.UpdatedBy).IsModified = true;
        
            var changes = await db.SaveChangesAsync();
        
            return Results.NoContent();
        }).RequireAuthorization();
        

        return app;
    }
}



