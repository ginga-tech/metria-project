using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using LifeBalance.Api.Data;
using LifeBalance.Api.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using LifeBalance.API.Models.Enums;

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;

var corsOrigin = builder.Environment.IsDevelopment()
    ? "http://localhost:5173"
    : (Environment.GetEnvironmentVariable("FRONTEND_ORIGIN") ?? "https://seu-dominio-frontend");

builder.Services.AddCors(o =>
{
    o.AddPolicy("frontend", p =>
        p.WithOrigins(corsOrigin).AllowAnyHeader().AllowAnyMethod().AllowCredentials());
});

var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]!));

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(opts =>
    {
        opts.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = config["Jwt:Issuer"],
            ValidAudience = config["Jwt:Audience"],
            IssuerSigningKey = key,
            ClockSkew = TimeSpan.FromSeconds(30)
        };
    });

builder.Services.AddAuthorization();

// Postgres (Neon) connection
var conn = Environment.GetEnvironmentVariable("POSTGRES_CONNECTION")
           ?? config.GetConnectionString("Postgres");
if (string.IsNullOrWhiteSpace(conn))
{
    throw new InvalidOperationException("Missing Postgres connection string. Set POSTGRES_CONNECTION or ConnectionStrings:Postgres");
}

builder.Services.AddDbContext<AppDbContext>(opt => 
    opt.UseNpgsql(conn, o => o.UseQuerySplittingBehavior(QuerySplittingBehavior.SplitQuery)));

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddHttpClient();

// Configure JSON options to handle string enums
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
});

var app = builder.Build();
app.UseCors("frontend");
app.UseAuthentication();
app.UseAuthorization();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Ensure database exists (migrate then ensure create for MVP)
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    try { db.Database.Migrate(); } catch { }
    db.Database.EnsureCreated();
}

string Hash(string s) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s)));

string CreateToken(string email)
{
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    var claims = new[]
    {
        new Claim(JwtRegisteredClaimNames.Sub, email),
        new Claim(JwtRegisteredClaimNames.Email, email)
    };
    var expires = DateTime.UtcNow.AddSeconds(int.Parse(config["Jwt:ExpiresInSeconds"]!));

    var token = new JwtSecurityToken(
        issuer: config["Jwt:Issuer"],
        audience: config["Jwt:Audience"],
        claims: claims,
        expires: expires,
        signingCredentials: creds);
    return new JwtSecurityTokenHandler().WriteToken(token);
}

bool IsValidEmail(string email) => new EmailAddressAttribute().IsValid(email);

app.MapPost("/api/auth/signup", async (SignupDto dto, AppDbContext db) =>
{
    var name = dto.Name?.Trim();
    var email = dto.Email?.Trim().ToLowerInvariant();
    var password = dto.Password ?? string.Empty;

    if (string.IsNullOrWhiteSpace(name) || name.Length < 2)
        return Results.BadRequest("Nome invalido.");
    if (string.IsNullOrWhiteSpace(email) || !IsValidEmail(email))
        return Results.BadRequest("E-mail invalido.");
    if (string.IsNullOrEmpty(password) || password.Length < 6)
        return Results.BadRequest("Senha deve ter ao menos 6 caracteres.");

    var exists = await db.Users.AsNoTracking().AnyAsync(u => u.Email == email);
    if (exists) return Results.BadRequest("Email ja cadastrado");

    var user = new User { Name = name!, Email = email!, PasswordHash = Hash(password) };
    db.Users.Add(user);
    await db.SaveChangesAsync();

    var token = CreateToken(email!);
    return Results.Ok(new { token, expiresInSeconds = int.Parse(config["Jwt:ExpiresInSeconds"]!) });
});

app.MapPost("/api/auth/login", async (LoginDto dto, AppDbContext db) =>
{
    var email = dto.Email?.Trim().ToLowerInvariant();
    var password = dto.Password ?? string.Empty;

    if (string.IsNullOrWhiteSpace(email) || !IsValidEmail(email))
        return Results.BadRequest("E-mail invalido.");
    if (string.IsNullOrEmpty(password))
        return Results.BadRequest("Senha obrigatoria.");

    var user = await db.Users.FirstOrDefaultAsync(u => u.Email == email);
    if (user is null) return Results.Unauthorized();
    if (!string.Equals(user.PasswordHash, Hash(password), StringComparison.Ordinal)) return Results.Unauthorized();

    var token = CreateToken(email!);
    return Results.Ok(new { token, expiresInSeconds = int.Parse(config["Jwt:ExpiresInSeconds"]!) });
});

app.MapGet("/api/me", (ClaimsPrincipal user) =>
{
    var email = user.FindFirstValue(ClaimTypes.Email) ?? user.FindFirstValue(JwtRegisteredClaimNames.Email);
    return Results.Ok(new { email });
}).RequireAuthorization();

app.MapGet("/api/user/preferences", async (ClaimsPrincipal user, AppDbContext db) =>
{
    var email = user.FindFirstValue(ClaimTypes.Email) ?? user.FindFirstValue(JwtRegisteredClaimNames.Email);
    if (string.IsNullOrWhiteSpace(email)) return Results.Unauthorized();

    var u = await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Email == email);
    if (u is null) return Results.Unauthorized();

    return Results.Ok(new {
        name = u.Name,
        email = u.Email,
        birthDate = u.BirthDate?.ToString("yyyy-MM-dd")
    });
}).RequireAuthorization();

app.MapPut("/api/user/preferences", async (ClaimsPrincipal user, UpdatePreferencesDto dto, AppDbContext db) =>
{
    var email = user.FindFirstValue(ClaimTypes.Email) ?? user.FindFirstValue(JwtRegisteredClaimNames.Email);
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
        if (DateTime.TryParse(dto.BirthDate, out var birthDate))
        {
            u.BirthDate = birthDate;
        }
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

app.MapGet("/api/user/status", async (ClaimsPrincipal user, AppDbContext db) =>
{
    var email = user.FindFirstValue(ClaimTypes.Email) ?? user.FindFirstValue(JwtRegisteredClaimNames.Email);
    if (string.IsNullOrWhiteSpace(email)) return Results.Unauthorized();

    var u = await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Email == email);
    if (u is null) return Results.Unauthorized();

    // Verifica se tem assessment
    var hasAssessment = await db.Assessments.AsNoTracking()
        .AnyAsync(a => a.UserId == u.Id);

    // Verifica se tem metas (temporariamente desabilitado at� a tabela ser criada)
    bool hasGoals = false;

    // Pega a data do �ltimo assessment
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

app.MapPost("/api/assessment", async (ClaimsPrincipal claimsPrincipal, AssessmentDto dto, AppDbContext db) =>
{
    var email = claimsPrincipal.FindFirstValue(ClaimTypes.Email) ?? claimsPrincipal.FindFirstValue(JwtRegisteredClaimNames.Email);
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

app.MapGet("/api/assessment/latest", async (ClaimsPrincipal user, AppDbContext db) =>
{
    var email = user.FindFirstValue(ClaimTypes.Email) ?? user.FindFirstValue(JwtRegisteredClaimNames.Email);
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

string Base64UrlEncode(string plain) {
    var bytes = Encoding.UTF8.GetBytes(plain);
    return Convert.ToBase64String(bytes).TrimEnd('=');
}
string Base64UrlDecode(string encoded) {
    string s = encoded.Replace('-', '+').Replace('_', '/');
    switch (s.Length % 4) { case 2: s += "=="; break; case 3: s += "="; break; }
    var bytes = Convert.FromBase64String(s);
    return Encoding.UTF8.GetString(bytes);
}

app.MapGet("/api/auth/google/start", (HttpContext ctx) =>
{
    var cfg = ctx.RequestServices.GetRequiredService<IConfiguration>();
    var clientId = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_ID") ?? cfg["Google:ClientId"];
    var backendBase = Environment.GetEnvironmentVariable("BACKEND_BASE_URL") ?? cfg["BackendBaseUrl"] ?? (ctx.Request.Scheme + "://" + ctx.Request.Host.Value);
    var callback = backendBase.TrimEnd('/') + "/api/auth/google/callback";
    if (string.IsNullOrWhiteSpace(clientId)) return Results.BadRequest("Missing Google ClientId");

    var frontRedirect = ctx.Request.Query["redirectUri"].ToString();
    if (string.IsNullOrWhiteSpace(frontRedirect)) frontRedirect = (cfg["FrontendCallback"] ?? "");
    var state = string.IsNullOrWhiteSpace(frontRedirect) ? "" : Convert.ToBase64String(Encoding.UTF8.GetBytes(frontRedirect));

    var authUrl = new StringBuilder("https://accounts.google.com/o/oauth2/v2/auth");
    authUrl.Append("?response_type=code");
    authUrl.Append("&client_id=").Append(Uri.EscapeDataString(clientId));
    authUrl.Append("&redirect_uri=").Append(Uri.EscapeDataString(callback));
    authUrl.Append("&scope=").Append(Uri.EscapeDataString("openid email profile"));
    authUrl.Append("&access_type=offline&include_granted_scopes=true&prompt=consent");
    if (!string.IsNullOrEmpty(state)) authUrl.Append("&state=").Append(Uri.EscapeDataString(state));

    return Results.Redirect(authUrl.ToString());
});

app.MapMethods("/api/auth/google/callback", new[] { "GET", "POST" }, async (HttpContext ctx, AppDbContext db) =>
{
    var cfg = ctx.RequestServices.GetRequiredService<IConfiguration>();
    var clientId = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_ID") ?? cfg["Google:ClientId"];
    var clientSecret = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_SECRET") ?? cfg["Google:ClientSecret"];
    var backendBase = Environment.GetEnvironmentVariable("BACKEND_BASE_URL") ?? cfg["BackendBaseUrl"] ?? (ctx.Request.Scheme + "://" + ctx.Request.Host.Value);
    var callback = backendBase.TrimEnd('/') + "/api/auth/google/callback";
    if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret)) return Results.BadRequest("Missing Google OAuth config");

    string code = ctx.Request.Query["code"].ToString();
    string state = ctx.Request.Query["state"].ToString();
    if (string.IsNullOrEmpty(code) && string.Equals(ctx.Request.Method, "POST", StringComparison.OrdinalIgnoreCase))
    {
        try {
            using var sr = new StreamReader(ctx.Request.Body);
            var body = await sr.ReadToEndAsync();
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("code", out var c)) code = c.GetString() ?? code;
            if (doc.RootElement.TryGetProperty("state", out var st)) state = st.GetString() ?? state;
        } catch {}
    }

    // Decide front: FrontendCallback > decode(state) > "/"
    var front = cfg["FrontendCallback"];
    if (string.IsNullOrEmpty(front) && !string.IsNullOrEmpty(state)) front = Encoding.UTF8.GetString(Convert.FromBase64String(state));
    if (string.IsNullOrEmpty(front)) front = "/";
    
    // CORRE��O: For�a sempre a porta 5173 para evitar problemas com configura��o do Google Console
    if (front.Contains("localhost:5174")) {
        front = front.Replace("localhost:5174", "localhost:5173");
    }

    if (string.IsNullOrEmpty(code))
        return Results.Redirect(front);

    var http = ctx.RequestServices.GetRequiredService<IHttpClientFactory>().CreateClient();
    var tokenResp = await http.PostAsync("https://oauth2.googleapis.com/token",
        new FormUrlEncodedContent(new Dictionary<string,string> {
            ["code"] = code,
            ["client_id"] = clientId!,
            ["client_secret"] = clientSecret!,
            ["redirect_uri"] = callback,
            ["grant_type"] = "authorization_code"
        }));
    if (!tokenResp.IsSuccessStatusCode)
    {
        var sep = front.Contains("?") ? "&" : "?";
        return Results.Redirect($"{front}{sep}code={Uri.EscapeDataString(code)}");
    }

    using var tokenJson = JsonDocument.Parse(await tokenResp.Content.ReadAsStringAsync());
    var accessToken = tokenJson.RootElement.GetProperty("access_token").GetString();
    if (string.IsNullOrEmpty(accessToken))
    {
        var sep = front.Contains("?") ? "&" : "?";
        return Results.Redirect($"{front}{sep}code={Uri.EscapeDataString(code)}");
    }

    var infoReq = new HttpRequestMessage(HttpMethod.Get, "https://openidconnect.googleapis.com/v1/userinfo");
    infoReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
    var infoResp = await http.SendAsync(infoReq);
    if (!infoResp.IsSuccessStatusCode)
    {
        var sep = front.Contains("?") ? "&" : "?";
        return Results.Redirect($"{front}{sep}code={Uri.EscapeDataString(code)}");
    }

    using var infoJson = JsonDocument.Parse(await infoResp.Content.ReadAsStringAsync());
    var email = infoJson.RootElement.TryGetProperty("email", out var e) ? e.GetString() ?? "" : "";
    var name = infoJson.RootElement.TryGetProperty("name", out var n) ? n.GetString() ?? email : email;
    if (string.IsNullOrWhiteSpace(email))
    {
        var sep = front.Contains("?") ? "&" : "?";
        return Results.Redirect($"{front}{sep}code={Uri.EscapeDataString(code)}");
    }

    email = email.ToLowerInvariant();
    var user = await db.Users.FirstOrDefaultAsync(u => u.Email == email);
    if (user is null)
    {
        user = new User { Email = email, Name = name, PasswordHash = "oauth_google" };
        db.Users.Add(user);
        await db.SaveChangesAsync();
    }

    var token = CreateToken(email);
    return Results.Redirect($"{front}#token={Uri.EscapeDataString(token)}");
});

// Goals endpoints
app.MapPost("/api/goals", async (ClaimsPrincipal user, CreateGoalDto dto, AppDbContext db) =>
{
    var email = user.FindFirstValue(ClaimTypes.Email) ?? user.FindFirstValue(JwtRegisteredClaimNames.Email);
    if (string.IsNullOrWhiteSpace(email)) return Results.Unauthorized();

    var u = await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Email == email);
    if (u is null) return Results.Unauthorized();

    if (string.IsNullOrWhiteSpace(dto.Text) || dto.Text.Length > 500)
        return Results.BadRequest("Texto da meta � obrigat�rio e deve ter no m�ximo 500 caracteres");

    if (!Enum.IsDefined(typeof(GoalPeriod), dto.Period))
        return Results.BadRequest("Per�odo da meta � inv�lido");

    if (dto.StartDate >= dto.EndDate)
        return Results.BadRequest("Data de in�cio deve ser anterior � data de fim");

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
        UpdatedAtUtc = DateTime.UtcNow
    };

    db.Goals.Add(goal);
    await db.SaveChangesAsync();

    return Results.Created($"/api/goals/{goal.Id}", new GoalDto(
        goal.Id, goal.Text, goal.Done, goal.Period.ToString(), 
        goal.StartDate.ToString("yyyy-MM-dd"), goal.EndDate.ToString("yyyy-MM-dd"),
        goal.Category, goal.CreatedAtUtc.ToString("O")
    ));
}).RequireAuthorization();

app.MapGet("/api/goals", async (ClaimsPrincipal user, AppDbContext db, string? period = null, string? startDate = null, string? endDate = null) =>
{
    var email = user.FindFirstValue(ClaimTypes.Email) ?? user.FindFirstValue(JwtRegisteredClaimNames.Email);
    if (string.IsNullOrWhiteSpace(email)) return Results.Unauthorized();

    var u = await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Email == email);
    if (u is null) return Results.Unauthorized();

    var query = db.Goals.AsNoTracking().Where(g => g.UserId == u.Id);

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

app.MapPut("/api/goals/{id:guid}", async (ClaimsPrincipal user, Guid id, UpdateGoalDto dto, AppDbContext db) =>
{
    var email = user.FindFirstValue(ClaimTypes.Email) ?? user.FindFirstValue(JwtRegisteredClaimNames.Email);
    if (string.IsNullOrWhiteSpace(email)) return Results.Unauthorized();

    var u = await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Email == email);
    if (u is null) return Results.Unauthorized();

    var goal = await db.Goals.FirstOrDefaultAsync(g => g.Id == id && g.UserId == u.Id);
    if (goal is null) return Results.NotFound();

    goal.Done = dto.Done;
    goal.UpdatedAtUtc = DateTime.UtcNow;

    await db.SaveChangesAsync();

    return Results.Ok(new GoalDto(
        goal.Id, goal.Text, goal.Done, goal.Period.ToString(),
        goal.StartDate.ToString("yyyy-MM-dd"), goal.EndDate.ToString("yyyy-MM-dd"),
        goal.Category, goal.CreatedAtUtc.ToString("O")
    ));
}).RequireAuthorization();

app.MapDelete("/api/goals/{id:guid}", async (ClaimsPrincipal user, Guid id, AppDbContext db) =>
{
    var email = user.FindFirstValue(ClaimTypes.Email) ?? user.FindFirstValue(JwtRegisteredClaimNames.Email);
    if (string.IsNullOrWhiteSpace(email)) return Results.Unauthorized();

    var u = await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Email == email);
    if (u is null) return Results.Unauthorized();

    var goal = await db.Goals.FirstOrDefaultAsync(g => g.Id == id && g.UserId == u.Id);
    if (goal is null) return Results.NotFound();

    db.Goals.Remove(goal);
    await db.SaveChangesAsync();

    return Results.NoContent();
}).RequireAuthorization();

app.Run();

record SignupDto(string Name, string Email, string Password);
record LoginDto(string Email, string Password);
record AssessmentDto(Dictionary<string,int> Scores, double Average, string CreatedAtUtc);
record GoalDto(Guid Id, string Text, bool Done, string Period, string StartDate, string EndDate, string? Category, string CreatedAtUtc);
record CreateGoalDto(string Text, GoalPeriod Period, DateTime StartDate, DateTime EndDate, string? Category);
record UpdateGoalDto(bool Done);
record UpdatePreferencesDto(string? Name, string? BirthDate);
