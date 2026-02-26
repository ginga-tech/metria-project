using Metria.Api.Auth;
using Metria.Api.Contracts;
using Metria.Api.Data;
using Metria.Api.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Text.Json;

namespace Metria.Api.Endpoints;

public static class AssessmentEndpoints
{
    public static WebApplication MapAssessmentEndpoints(this WebApplication app)
    {
        const string Tag = "Assessment";
        var assessment = app.MapGroup("/api/assessment").WithTags(Tag);

        assessment.MapPost("", async (ClaimsPrincipal claimsPrincipal, AssessmentDto dto, [FromServices] AppDbContext db) =>
        {
            var email = claimsPrincipal.GetEmail();
            if (string.IsNullOrWhiteSpace(email)) return Results.Unauthorized();
        
            var user = await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Email == email);
            if (user is null) return Results.Unauthorized();
        
            var entity = new Assessment
            {
                UserId = user.Id,
                ScoresJson = JsonSerializer.Serialize(dto.Scores),
                Average = dto.Average,
                CreatedAtUtc = DateTime.UtcNow
            };
            db.Assessments.Add(entity);
            await db.SaveChangesAsync();
        
            return Results.Created($"/api/assessment/latest", new { ok = true });
        }).RequireAuthorization();
        
        assessment.MapGet("/latest", async (ClaimsPrincipal user, [FromServices] AppDbContext db) =>
        {
            var email = user.GetEmail();
            if (string.IsNullOrWhiteSpace(email)) return Results.Unauthorized();
        
            var u = await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Email == email);
            if (u is null) return Results.Unauthorized();
        
            var last = await db.Assessments.AsNoTracking()
                .Where(a => a.UserId == u.Id)
                .OrderByDescending(a => a.CreatedAtUtc)
                .FirstOrDefaultAsync();
        
            if (last is null) return Results.NotFound();
        
            var scores = JsonSerializer.Deserialize<Dictionary<string,int>>(last.ScoresJson) ?? new();
            return Results.Ok(new AssessmentDto(scores, last.Average, last.CreatedAtUtc.ToString("O")));
        }).RequireAuthorization();
        

        return app;
    }
}



