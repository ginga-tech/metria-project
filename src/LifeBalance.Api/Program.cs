using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

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

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();
app.UseCors("frontend");
app.UseAuthentication();
app.UseAuthorization();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// MVP: store in-memory
var users = new Dictionary<string, (string Name, string Hash)>();

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

app.MapPost("/api/auth/signup", (SignupDto dto) =>
{
    if (users.ContainsKey(dto.Email)) return Results.BadRequest("Email j� cadastrado");
    users[dto.Email] = (dto.Name, Hash(dto.Password));
    var token = CreateToken(dto.Email);
    return Results.Ok(new { token, expiresInSeconds = int.Parse(config["Jwt:ExpiresInSeconds"]!) });
});

app.MapPost("/api/auth/login", (LoginDto dto) =>
{
    if (!users.TryGetValue(dto.Email, out var u)) return Results.Unauthorized();
    if (u.Hash != Hash(dto.Password)) return Results.Unauthorized();
    var token = CreateToken(dto.Email);
    return Results.Ok(new { token, expiresInSeconds = int.Parse(config["Jwt:ExpiresInSeconds"]!) });
});

app.MapGet("/api/me", (ClaimsPrincipal user) =>
{
    var email = user.FindFirstValue(ClaimTypes.Email);
    return Results.Ok(new { email });
}).RequireAuthorization();

app.Run();

record SignupDto(string Name, string Email, string Password);
record LoginDto(string Email, string Password);

