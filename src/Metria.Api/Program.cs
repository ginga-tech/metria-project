using Metria.Api.Data;
using Metria.Api.Endpoints;
using Metria.Api.Repositories;
using Metria.Api.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Text.Json.Serialization;

// Load .env file
DotNetEnv.Env.Load();

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;

// Stripe API Key (from env STRIPE_SECRET_KEY or config Stripe:SecretKey)
var stripeSecret = Environment.GetEnvironmentVariable("STRIPE_SECRET_KEY") ?? config["Stripe:SecretKey"];
if (!string.IsNullOrWhiteSpace(stripeSecret))
{
    Stripe.StripeConfiguration.ApiKey = stripeSecret;
}

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
builder.Services.AddMemoryCache();
builder.Services.AddScoped<ISubscriptionRepository, SubscriptionRepository>();
builder.Services.AddScoped<ISubscriptionService, SubscriptionService>();

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
    app.UseSwaggerUI(c =>
    {
        c.RoutePrefix = "";
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Metria.Api v1");
    });
}

app.MapGet("/health-check", () => Results.Ok(new { ok = true, timeUtc = DateTime.UtcNow }))
   .AllowAnonymous();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    try { db.Database.Migrate(); } catch { }
}

app.MapAuthEndpoints(config, key);
app.MapUserEndpoints();
app.MapBillingEndpoints();
app.MapAssessmentEndpoints();
app.MapGoalsEndpoints();

app.Run();

