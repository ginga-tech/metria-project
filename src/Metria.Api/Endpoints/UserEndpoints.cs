using Metria.Api.Auth;
using Metria.Api.Contracts;
using Metria.Api.Data;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Globalization;
using System.Security.Claims;

namespace Metria.Api.Endpoints;

public static class UserEndpoints
{
    public static WebApplication MapUserEndpoints(this WebApplication app)
    {
        const string Tag = "User";
        var api = app.MapGroup("/api").WithTags(Tag);
        var userGroup = app.MapGroup("/api/user").WithTags(Tag);

        api.MapGet("/me", (ClaimsPrincipal user) =>
        {
            var email = user.GetEmail();
            return Results.Ok(new { email });
        }).RequireAuthorization();
        
        userGroup.MapGet("/preferences", async (ClaimsPrincipal user, [FromServices] AppDbContext db) =>
        {
            var email = user.GetEmail();
            if (string.IsNullOrWhiteSpace(email)) return Results.Unauthorized();
        
            var u = await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Email == email);
            if (u is null) return Results.Unauthorized();
        
            return Results.Ok(new {
                name = u.Name,
                email = u.Email,
                birthDate = u.BirthDate?.ToString("yyyy-MM-dd")
            });
        }).RequireAuthorization();
        
        userGroup.MapPut("/preferences", async (ClaimsPrincipal user, UpdatePreferencesDto dto, [FromServices] AppDbContext db) =>
        {
            var email = user.GetEmail();
            if (string.IsNullOrWhiteSpace(email)) return Results.Unauthorized();
        
            var u = await db.Users.FirstOrDefaultAsync(x => x.Email == email);
            if (u is null) return Results.Unauthorized();
        
            // Atualiza nome se fornecido
            if (!string.IsNullOrWhiteSpace(dto.Name))
            {
                u.Name = dto.Name.Trim();
            }
        
            // Atualiza data de nascimento se fornecida
            if (!string.IsNullOrWhiteSpace(dto.BirthDate))
            {
                if (DateTime.TryParseExact(dto.BirthDate, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var birthDate)) { u.BirthDate = DateTime.SpecifyKind(birthDate, DateTimeKind.Unspecified); }
            }
            else
            {
                u.BirthDate = null;
            }
        
            await db.SaveChangesAsync();
        
            return Results.Ok(new {
                name = u.Name,
                email = u.Email,
                birthDate = u.BirthDate?.ToString("yyyy-MM-dd")
            });
        }).RequireAuthorization();
        
        userGroup.MapGet("/status", async (ClaimsPrincipal user, [FromServices] AppDbContext db) =>
        {
            var email = user.GetEmail();
            if (string.IsNullOrWhiteSpace(email)) return Results.Unauthorized();
        
            var u = await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Email == email);
            if (u is null) return Results.Unauthorized();
        
            // Verifica se tem assessment
            var hasAssessment = await db.Assessments.AsNoTracking()
                .AnyAsync(a => a.UserId == u.Id);
        
            // Verifica se tem metas (temporariamente desabilitado até a tabela ser criada)
            bool hasGoals = false;
        
            // Pega a data do úlltimo assessment
            var lastAssessment = await db.Assessments.AsNoTracking()
                .Where(a => a.UserId == u.Id)
                .OrderByDescending(a => a.CreatedAtUtc)
                .Select(a => a.CreatedAtUtc)
                .FirstOrDefaultAsync();
        
            return Results.Ok(new {
                hasAssessment,
                hasGoals,
                lastAssessmentDate = lastAssessment == default ? (DateTime?)null : lastAssessment,
                email = u.Email,
                name = u.Name
            });
        }).RequireAuthorization();

        return app;
    }
}





