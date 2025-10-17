using LifeBalance.Api.Data;
using LifeBalance.Api.Models;
using LifeBalance.Api.Repositories;
using LifeBalance.Api.Services;
using LifeBalance.API.Models.Enums;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;
using Stripe;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using BillingPortalSessionCreateOptions = Stripe.BillingPortal.SessionCreateOptions;
using BillingPortalSessionService = Stripe.BillingPortal.SessionService;
using CheckoutLineItemOptions = Stripe.Checkout.SessionLineItemOptions;
using CheckoutSession = Stripe.Checkout.Session;
using CheckoutSessionCreateOptions = Stripe.Checkout.SessionCreateOptions;
using CheckoutSessionService = Stripe.Checkout.SessionService;
using DbSubscription = LifeBalance.Api.Models.Subscription;
using StripeSubscription = Stripe.Subscription;
using StripeSubscriptionService = Stripe.SubscriptionService;

// Load .env file
DotNetEnv.Env.Load();

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;
// Stripe API Key (from env STRIPE_SECRET_KEY or config Stripe:SecretKey)
var stripeSecret = Environment.GetEnvironmentVariable("STRIPE_SECRET_KEY") ?? config["Stripe:SecretKey"]; 
if (!string.IsNullOrWhiteSpace(stripeSecret)) {
    StripeConfiguration.ApiKey = stripeSecret;
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
builder.Services.AddMemoryCache();
builder.Services.AddScoped<ISubscriptionRepository, SubscriptionRepository>();
builder.Services.AddScoped<ISubscriptionService, LifeBalance.Api.Services.SubscriptionService>();

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

// Health check simples
app.MapGet("/healthz", () => Results.Ok(new { ok = true, timeUtc = DateTime.UtcNow }))
   .AllowAnonymous();

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

app.MapPost("/api/auth/signup", async (SignupDto dto, [FromServices] AppDbContext db) =>
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

app.MapPost("/api/auth/login", async (LoginDto dto, [FromServices] AppDbContext db) =>
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

app.MapGet("/api/user/preferences", async (ClaimsPrincipal user, [FromServices] AppDbContext db) =>
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

app.MapPut("/api/user/preferences", async (ClaimsPrincipal user, UpdatePreferencesDto dto, [FromServices] AppDbContext db) =>
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

app.MapGet("/api/user/status", async (ClaimsPrincipal user, [FromServices] AppDbContext db) =>
{
    var email = user.FindFirstValue(ClaimTypes.Email) ?? user.FindFirstValue(JwtRegisteredClaimNames.Email);
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

// Billing: subscription status (used by frontend paywall)
app.MapGet("/api/billing/subscription", async (ClaimsPrincipal user, [FromServices] AppDbContext db, [FromServices] ISubscriptionService svc, [FromServices] IConfiguration cfg, [FromServices] ILogger<Program> log, [FromServices] IMemoryCache cache) =>
{
    var email = user.FindFirstValue(ClaimTypes.Email) ?? user.FindFirstValue(JwtRegisteredClaimNames.Email);
    if (string.IsNullOrWhiteSpace(email)) return Results.Unauthorized();

    var u = await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Email == email);
    if (u is null) return Results.Unauthorized();

    var (active, plan, renewsAtUtc) = await svc.GetStatusAsync(u.Id);
    if (!active)
    {
        try
        {
            log.LogInformation("No active sub in DB for {Email}. Attempting on-demand Stripe sync...", email);
            var throttleKey = $"sub_sync_recent_{u.Id}";
            if (cache.TryGetValue(throttleKey, out _))
            {
                log.LogInformation("On-demand Stripe sync throttled for user {UserId}", u.Id);
                goto SkipSync;
            }

            string? MonthlyPriceId() => Environment.GetEnvironmentVariable("STRIPE_MONTHLY_PRICE_ID") ?? cfg["Stripe:MonthlyPriceId"];
            string? AnnualPriceId() => Environment.GetEnvironmentVariable("STRIPE_ANNUAL_PRICE_ID") ?? cfg["Stripe:AnnualPriceId"];
            SubscriptionPlan MapPlan(string? priceId, string? interval)
            {
                if (!string.IsNullOrWhiteSpace(priceId))
                {
                    if (!string.IsNullOrWhiteSpace(MonthlyPriceId()) && priceId == MonthlyPriceId()) return SubscriptionPlan.Monthly;
                    if (!string.IsNullOrWhiteSpace(AnnualPriceId()) && priceId == AnnualPriceId()) return SubscriptionPlan.Annual;
                }
                if (!string.IsNullOrWhiteSpace(interval))
                {
                    if (string.Equals(interval, "month", StringComparison.OrdinalIgnoreCase)) return SubscriptionPlan.Monthly;
                    if (string.Equals(interval, "year", StringComparison.OrdinalIgnoreCase)) return SubscriptionPlan.Annual;
                }
                return SubscriptionPlan.Monthly;
            }
            SubscriptionStatus MapStatus(string? status) => (status ?? string.Empty).ToLowerInvariant() switch
            {
                "incomplete" => SubscriptionStatus.Incomplete,
                "incomplete_expired" => SubscriptionStatus.IncompleteExpired,
                "trialing" => SubscriptionStatus.Trialing,
                "active" => SubscriptionStatus.Active,
                "past_due" => SubscriptionStatus.PastDue,
                "canceled" => SubscriptionStatus.Canceled,
                "unpaid" => SubscriptionStatus.Unpaid,
                _ => SubscriptionStatus.Incomplete
            };
            static DateTime? StripeDate(StripeSubscription s, string prop)
            {
                var p = s.GetType().GetProperty(prop);
                var v = p?.GetValue(s);
                if (v is DateTime dt) return dt.ToUniversalTime();
                if (v is long l) return DateTimeOffset.FromUnixTimeSeconds(l).UtcDateTime;
                return null;
            }

            var custService = new Stripe.CustomerService();
            var subService = new StripeSubscriptionService();

            var custs = await custService.ListAsync(new Stripe.CustomerListOptions { Email = email, Limit = 10 });
            var now = DateTime.UtcNow;
            StripeSubscription? found = null;
            foreach (var cust in custs.Data?.OrderByDescending(c => c.Created) ?? Enumerable.Empty<Customer>())
            {
                var list = await subService.ListAsync(new Stripe.SubscriptionListOptions { Customer = cust.Id, Limit = 10, Status = "all" });
                var candidate = list.Data?
                    .Where(s => s.Status == "active" || s.Status == "trialing")
                    .OrderByDescending(s => StripeDate(s, "CurrentPeriodEnd") ?? DateTime.MinValue)
                    .FirstOrDefault();
                if (candidate != null)
                {
                    found = candidate;
                    break;
                }
            }

            if (found == null)
            {
                // Fallback: search recent subscriptions (last 24h) and match by customer email
                try
                {
                    var cutoff = DateTimeOffset.UtcNow.AddHours(-24);
                    var recent = await subService.ListAsync(new Stripe.SubscriptionListOptions
                    {
                        Created = new DateRangeOptions { GreaterThanOrEqual = cutoff.DateTime },
                        Status = "all",
                        Limit = 50
                    });
                    foreach (var s in recent.Data?.Where(x => x.Status == "active" || x.Status == "trialing") ?? Enumerable.Empty<StripeSubscription>())
                    {
                        if (!string.IsNullOrWhiteSpace(s.CustomerId))
                        {
                            try
                            {
                                var customer = await custService.GetAsync(s.CustomerId);
                                if (string.Equals(customer.Email, email, StringComparison.OrdinalIgnoreCase))
                                {
                                    found = s;
                                    break;
                                }
                            }
                            catch { /* ignore */ }
                        }
                    }
                }
                catch (Exception ex)
                {
                    log.LogWarning(ex, "Failed recent subscriptions search for {Email}", email);
                }
            }

            if (found != null)
            {
                var price = found.Items?.Data?.FirstOrDefault()?.Price;
                var priceId = price?.Id;
                var interval = price?.Recurring?.Interval;
                var mappedPlan = MapPlan(priceId, interval);
                var mappedStatus = MapStatus(found.Status);
                var start = StripeDate(found, "CurrentPeriodStart");
                var end = StripeDate(found, "CurrentPeriodEnd");
                if (start != null && end != null)
                {
                    await svc.UpsertAsync(u.Id, mappedPlan, mappedStatus, start.Value, end.Value, found.CustomerId, found.Id, priceId);
                    (active, plan, renewsAtUtc) = await svc.GetStatusAsync(u.Id);
                    log.LogInformation("On-demand Stripe sync succeeded for {Email}. active={Active}, plan={Plan}", email, active, plan);
                }
                else
                {
                    log.LogWarning("Found Stripe subscription but missing period dates for {Email}", email);
                }
            }
            else
            {
                log.LogInformation("No Stripe subscription found by email for {Email}", email);
            }

            // Throttle subsequent attempts for a short period
            cache.Set(throttleKey, true, TimeSpan.FromSeconds(20));
        }
        catch (Exception ex)
        {
            log.LogWarning(ex, "On-demand Stripe sync failed for {Email}", email);
        }
        SkipSync:;
    }

    log.LogInformation("GET /api/billing/subscription -> user {Email} ({UserId}) active={Active} plan={Plan} renewsAt={Renews}", email, u.Id, active, plan?.ToString(), renewsAtUtc);
    return Results.Ok(new { active, plan = plan?.ToString().ToLowerInvariant(), renewsAtUtc });
}).RequireAuthorization();

// Billing: subscriptions history
app.MapGet("/api/billing/subscriptions/history", async (ClaimsPrincipal user, [FromServices] AppDbContext db, [FromServices] ILogger<Program> log) =>
{
    var email = user.FindFirstValue(ClaimTypes.Email) ?? user.FindFirstValue(JwtRegisteredClaimNames.Email);
    if (string.IsNullOrWhiteSpace(email)) return Results.Unauthorized();

    var u = await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Email == email);
    if (u is null) return Results.Unauthorized();

    var list = await db.Subscriptions.AsNoTracking()
        .Where(s => s.UserId == u.Id)
        .OrderByDescending(s => s.CreatedAtUtc)
        .Select(s => new {
            provider = s.Provider,
            plan = s.Plan.ToString().ToLowerInvariant(),
            status = s.Status.ToString().ToLowerInvariant(),
            startedAtUtc = s.StartedAtUtc,
            currentPeriodStartUtc = s.CurrentPeriodStartUtc,
            currentPeriodEndUtc = s.CurrentPeriodEndUtc,
            canceledAtUtc = s.CanceledAtUtc,
            createdAtUtc = s.CreatedAtUtc,
            updatedAtUtc = s.UpdatedAtUtc
        })
        .ToListAsync();

    log.LogInformation("GET /api/billing/subscriptions/history -> user {Email} ({UserId}) items={Count}", email, u.Id, list.Count);
    return Results.Ok(list);
}).RequireAuthorization();

// Billing: create Checkout Session (Stripe)
app.MapPost("/api/billing/checkout", async (ClaimsPrincipal user, CheckoutReq req, [FromServices] AppDbContext db, [FromServices] IConfiguration cfg, [FromServices] ILogger<Program> log) =>
{
    var email = user.FindFirstValue(ClaimTypes.Email) ?? user.FindFirstValue(JwtRegisteredClaimNames.Email);
    if (string.IsNullOrWhiteSpace(email)) return Results.Unauthorized();

    var u = await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Email == email);
    if (u is null) return Results.Unauthorized();

    if (string.IsNullOrWhiteSpace(req?.PriceId)) return Results.BadRequest("priceId obrigatório");

    var successUrl = string.IsNullOrWhiteSpace(req.SuccessUrl)
        ? ($"{(cfg["FrontendOrigin"] ?? "http://localhost:5173").TrimEnd('/')}/dashboard?checkout=success")
        : req.SuccessUrl;
    var cancelUrl = string.IsNullOrWhiteSpace(req.CancelUrl)
        ? ($"{(cfg["FrontendOrigin"] ?? "http://localhost:5173").TrimEnd('/')}/dashboard?checkout=cancel")
        : req.CancelUrl;

    // Tenta vincular a sessão a um Customer do Stripe com o e-mail do usuário
    string? customerId = null;
    try
    {
        customerId = await db.Subscriptions.AsNoTracking()
            .Where(s => s.UserId == u.Id && s.Provider == "stripe" && s.ProviderCustomerId != null)
            .OrderByDescending(s => s.UpdatedAtUtc)
            .Select(s => s.ProviderCustomerId)
            .FirstOrDefaultAsync();

        if (string.IsNullOrWhiteSpace(customerId))
        {
            var custService = new Stripe.CustomerService();
            var list = await custService.ListAsync(new Stripe.CustomerListOptions { Email = u.Email, Limit = 1 });
            var existing = list.Data?.FirstOrDefault();
            if (existing != null)
            {
                customerId = existing.Id;
            }
            else
            {
                var created = await custService.CreateAsync(new Stripe.CustomerCreateOptions { Email = u.Email });
                customerId = created?.Id;
            }
        }
    }
    catch (Exception ex)
    {
        log.LogWarning(ex, "Failed to resolve/create Stripe customer for {Email}", u.Email);
    }

    var options = new CheckoutSessionCreateOptions
    {
        Mode = "subscription",
        SuccessUrl = successUrl,
        CancelUrl = cancelUrl,
        ClientReferenceId = u.Id.ToString(),
        LineItems = new List<CheckoutLineItemOptions>
        {
            new CheckoutLineItemOptions { Price = req.PriceId, Quantity = 1 }
        }
    };
    if (!string.IsNullOrWhiteSpace(customerId))
    {
        options.Customer = customerId;
    }
    else
    {
        options.CustomerEmail = u.Email;
    }

    var service = new CheckoutSessionService();
    log.LogInformation("POST /api/billing/checkout -> user {Email} ({UserId}) price={PriceId} success={Success} cancel={Cancel}", email, u.Id, req.PriceId, successUrl, cancelUrl);
    var session = await service.CreateAsync(options);
    log.LogInformation("Checkout Session created: id={SessionId} url={Url}", session.Id, session.Url);
    return Results.Ok(new { url = session.Url });
}).RequireAuthorization();

// Billing: Customer Portal
app.MapPost("/api/billing/portal", async (ClaimsPrincipal user, PortalReq req, [FromServices] AppDbContext db, [FromServices] IConfiguration cfg, [FromServices] ILogger<Program> log) =>
{
    var email = user.FindFirstValue(ClaimTypes.Email) ?? user.FindFirstValue(JwtRegisteredClaimNames.Email);
    if (string.IsNullOrWhiteSpace(email)) return Results.Unauthorized();

    var u = await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Email == email);
    if (u is null) return Results.Unauthorized();

    var sub = await db.Subscriptions.AsNoTracking()
        .Where(s => s.UserId == u.Id)
        .OrderByDescending(s => s.UpdatedAtUtc)
        .FirstOrDefaultAsync();
    var customerId = sub?.ProviderCustomerId;
    if (string.IsNullOrWhiteSpace(customerId)) {
        log.LogWarning("/api/billing/portal -> user {Email} ({UserId}) sem ProviderCustomerId", email, u.Id);
        return Results.BadRequest("Cliente Stripe não encontrado.");
    }

    var billingPortal = new BillingPortalSessionService();
    var portalSession = await billingPortal.CreateAsync(new BillingPortalSessionCreateOptions
    {
        Customer = customerId,
        ReturnUrl = string.IsNullOrWhiteSpace(req?.ReturnUrl)
            ? ($"{(cfg["FrontendOrigin"] ?? "http://localhost:5173").TrimEnd('/')}/dashboard")
            : req.ReturnUrl
    });
    log.LogInformation("Billing portal created for user {Email} ({UserId}) customer={CustomerId} url={Url}", email, u.Id, customerId, portalSession.Url);
    return Results.Ok(new { url = portalSession.Url });
}).RequireAuthorization();

// Billing: Stripe Webhook - Enhanced with better error handling and logging
app.MapPost("/api/billing/webhook", async (HttpRequest http, [FromServices] AppDbContext db, [FromServices] IConfiguration cfg, [FromServices] ILogger<Program> log, [FromServices] IMemoryCache cache) =>
{
    using var reader = new StreamReader(http.Body);
    var json = await reader.ReadToEndAsync();
    var signature = http.Headers["Stripe-Signature"].ToString();
    var webhookSecret = Environment.GetEnvironmentVariable("STRIPE_WEBHOOK_SECRET") ?? cfg["Stripe:WebhookSecret"];
    
    if (string.IsNullOrWhiteSpace(webhookSecret)) 
    {
        log.LogError("Webhook secret not configured");
        return Results.BadRequest("Webhook secret não configurado");
    }

    Event stripeEvent;
    try 
    {
        stripeEvent = EventUtility.ConstructEvent(json, signature, webhookSecret);
    } 
    catch (Exception ex) 
    {
        log.LogError(ex, "Stripe webhook signature validation failed. HasSig={HasSig} PayloadLen={Len}", 
            !string.IsNullOrWhiteSpace(signature), json?.Length ?? 0);
        return Results.BadRequest("Invalid webhook signature");
    }

    log.LogInformation("Stripe webhook event received: type={Type} id={Id}", stripeEvent.Type, stripeEvent.Id);

    // Simple idempotency check using cache
    var cacheKey = $"webhook_processed_{stripeEvent.Id}";
    if (cache.TryGetValue(cacheKey, out _))
    {
        log.LogInformation("Webhook event {EventId} already processed, skipping", stripeEvent.Id);
        return Results.Ok(new { processed = true, eventId = stripeEvent.Id, cached = true });
    }

    try
    {
        // Process webhook based on type
        var success = await ProcessWebhookEvent(stripeEvent, db, cfg, log);
        
        if (success)
        {
            // Cache successful processing for 24 hours
            cache.Set(cacheKey, DateTime.UtcNow, TimeSpan.FromHours(24));
            log.LogInformation("Webhook event {EventId} processed successfully", stripeEvent.Id);
            return Results.Ok(new { processed = true, eventId = stripeEvent.Id });
        }
        else
        {
            log.LogWarning("Webhook event {EventId} processing failed", stripeEvent.Id);
            return Results.StatusCode(500);
        }
    }
    catch (Exception ex)
    {
        log.LogError(ex, "Unexpected error processing webhook event {EventId}", stripeEvent.Id);
        return Results.StatusCode(500);
    }
});

// Helper method to process webhook events
static async Task<bool> ProcessWebhookEvent(Event stripeEvent, AppDbContext db, IConfiguration cfg, ILogger<Program> log)
{
    // Helper functions for mapping
    string? MonthlyPriceId() => Environment.GetEnvironmentVariable("STRIPE_MONTHLY_PRICE_ID") ?? cfg["Stripe:MonthlyPriceId"];
    string? AnnualPriceId() => Environment.GetEnvironmentVariable("STRIPE_ANNUAL_PRICE_ID") ?? cfg["Stripe:AnnualPriceId"];

    SubscriptionPlan MapPlan(string? priceId, string? interval)
    {
        if (!string.IsNullOrWhiteSpace(priceId))
        {
            if (!string.IsNullOrWhiteSpace(MonthlyPriceId()) && priceId == MonthlyPriceId()) return SubscriptionPlan.Monthly;
            if (!string.IsNullOrWhiteSpace(AnnualPriceId()) && priceId == AnnualPriceId()) return SubscriptionPlan.Annual;
        }
        if (!string.IsNullOrWhiteSpace(interval))
        {
            if (string.Equals(interval, "month", StringComparison.OrdinalIgnoreCase)) return SubscriptionPlan.Monthly;
            if (string.Equals(interval, "year", StringComparison.OrdinalIgnoreCase)) return SubscriptionPlan.Annual;
        }
        return SubscriptionPlan.Monthly;
    }

    SubscriptionStatus MapStatus(string? status) => (status ?? string.Empty).ToLowerInvariant() switch
    {
        "incomplete" => SubscriptionStatus.Incomplete,
        "incomplete_expired" => SubscriptionStatus.IncompleteExpired,
        "trialing" => SubscriptionStatus.Trialing,
        "active" => SubscriptionStatus.Active,
        "past_due" => SubscriptionStatus.PastDue,
        "canceled" => SubscriptionStatus.Canceled,
        "unpaid" => SubscriptionStatus.Unpaid,
        _ => SubscriptionStatus.Incomplete
    };

    static DateTime? StripeDate(StripeSubscription s, string prop)
    {
        var p = s.GetType().GetProperty(prop);
        var v = p?.GetValue(s);
        if (v is DateTime dt) return dt.ToUniversalTime();
        if (v is long l) return DateTimeOffset.FromUnixTimeSeconds(l).UtcDateTime;
        return null;
    }

    try
    {
        switch (stripeEvent.Type)
        {
            case "checkout.session.completed":
                {
                    var session = stripeEvent.Data.Object as CheckoutSession;
                    if (session == null) return false;

                    log.LogInformation("Processing checkout.session.completed: sessionId={SessionId} customer={Customer} subscription={Subscription} clientRef={ClientRef}",
                        session.Id, session.Customer, session.Subscription, session.ClientReferenceId);

                    // Resolve user
                    Guid userId = Guid.Empty;
                    var clientRef = session.ClientReferenceId;
                    if (!string.IsNullOrWhiteSpace(clientRef))
                    {
                        if (Guid.TryParse(clientRef, out var uid))
                        {
                            userId = uid;
                        }
                        else
                        {
                            var u = await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Email == clientRef);
                            if (u != null) userId = u.Id;
                        }
                    }
                    if (userId == Guid.Empty)
                    {
                        var email = session.CustomerDetails?.Email ?? session.CustomerEmail;
                        if (!string.IsNullOrWhiteSpace(email))
                        {
                            var u = await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Email == email);
                            if (u != null) userId = u.Id;
                        }
                    }

                    if (userId == Guid.Empty)
                    {
                        log.LogWarning("Could not resolve user from checkout session {SessionId}", session.Id);
                        return false;
                    }

                    // Process subscription if present
                    if (!string.IsNullOrWhiteSpace(session.SubscriptionId))
                    {
                        var subsService = new StripeSubscriptionService();
                        var sub = await subsService.GetAsync(session.SubscriptionId);
                        await UpsertSubscription(sub, userId, db, MapPlan, MapStatus, StripeDate, log);
                    }

                    return true;
                }

            case "customer.subscription.created":
            case "customer.subscription.updated":
            case "customer.subscription.deleted":
                {
                    var sub = stripeEvent.Data.Object as StripeSubscription;
                    if (sub == null) return false;

                    log.LogInformation("Processing {EventType}: subId={SubId} customer={CustomerId} status={Status}",
                        stripeEvent.Type, sub.Id, sub.CustomerId, sub.Status);

                    // Resolve user
                    Guid userId = Guid.Empty;
                    var existingBySub = await db.Subscriptions.AsNoTracking().FirstOrDefaultAsync(s => s.ProviderSubscriptionId == sub.Id);
                    if (existingBySub != null) userId = existingBySub.UserId;

                    if (userId == Guid.Empty && !string.IsNullOrWhiteSpace(sub.CustomerId))
                    {
                        var existingByCustomer = await db.Subscriptions.AsNoTracking().FirstOrDefaultAsync(s => s.ProviderCustomerId == sub.CustomerId);
                        if (existingByCustomer != null) userId = existingByCustomer.UserId;
                    }

                    if (userId == Guid.Empty && !string.IsNullOrWhiteSpace(sub.CustomerId))
                    {
                        try
                        {
                            var cs = new CustomerService();
                            var cust = await cs.GetAsync(sub.CustomerId);
                            var email = cust?.Email;
                            if (!string.IsNullOrWhiteSpace(email))
                            {
                                var u = await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Email == email);
                                if (u != null) userId = u.Id;
                            }
                        }
                        catch (Exception ex)
                        {
                            log.LogWarning(ex, "Failed to fetch customer {CustomerId} from Stripe", sub.CustomerId);
                        }
                    }

                    if (userId == Guid.Empty)
                    {
                        log.LogWarning("Could not resolve user from subscription {SubscriptionId}", sub.Id);
                        return false;
                    }

                    await UpsertSubscription(sub, userId, db, MapPlan, MapStatus, StripeDate, log);
                    return true;
                }

            default:
                log.LogInformation("Unhandled webhook event type: {Type}", stripeEvent.Type);
                return true; // Not an error, just unhandled
        }
    }
    catch (Exception ex)
    {
        log.LogError(ex, "Error processing webhook event {EventId} type {Type}", stripeEvent.Id, stripeEvent.Type);
        return false;
    }
}

// Helper method to upsert subscription
static async Task UpsertSubscription(StripeSubscription stripeSubscription, Guid userId, AppDbContext db, 
    Func<string?, string?, SubscriptionPlan> mapPlan, Func<string?, SubscriptionStatus> mapStatus, 
    Func<StripeSubscription, string, DateTime?> stripeDate, ILogger<Program> log)
{
    var price = stripeSubscription.Items?.Data?.FirstOrDefault()?.Price;
    var priceId = price?.Id;
    var interval = price?.Recurring?.Interval;
    var plan = mapPlan(priceId, interval);
    var status = mapStatus(stripeSubscription.Status);

    var start = stripeDate(stripeSubscription, "CurrentPeriodStart");
    var end = stripeDate(stripeSubscription, "CurrentPeriodEnd");

    if (start == null || end == null)
    {
        log.LogWarning("Subscription {SubscriptionId} missing current period dates", stripeSubscription.Id);
        return;
    }

    // Cancel other active subscriptions for this user
    var activeSubscriptions = await db.Subscriptions
        .Where(s => s.UserId == userId &&
                   (s.Status == SubscriptionStatus.Active || s.Status == SubscriptionStatus.Trialing) &&
                   s.ProviderSubscriptionId != stripeSubscription.Id)
        .ToListAsync();

    foreach (var activeSub in activeSubscriptions)
    {
        activeSub.Status = SubscriptionStatus.Canceled;
        activeSub.CanceledAtUtc = DateTime.UtcNow;
        activeSub.UpdatedAtUtc = DateTime.UtcNow;
    }

    // Upsert current subscription
    var subscription = await db.Subscriptions
        .FirstOrDefaultAsync(s => s.ProviderSubscriptionId == stripeSubscription.Id);

    if (subscription == null)
    {
        subscription = new DbSubscription
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            Provider = "stripe",
            ProviderCustomerId = stripeSubscription.CustomerId,
            ProviderSubscriptionId = stripeSubscription.Id,
            ProviderPriceId = priceId,
            Plan = plan,
            Status = status,
            StartedAtUtc = (status == SubscriptionStatus.Active || status == SubscriptionStatus.Trialing) ? DateTime.UtcNow : null,
            CurrentPeriodStartUtc = start.Value,
            CurrentPeriodEndUtc = end.Value,
            CreatedAtUtc = DateTime.UtcNow,
            UpdatedAtUtc = DateTime.UtcNow
        };
        db.Subscriptions.Add(subscription);
    }
    else
    {
        subscription.UserId = userId;
        subscription.ProviderCustomerId = stripeSubscription.CustomerId;
        subscription.ProviderPriceId = priceId ?? subscription.ProviderPriceId;
        subscription.Plan = plan;
        subscription.Status = status;
        subscription.CurrentPeriodStartUtc = start.Value;
        subscription.CurrentPeriodEndUtc = end.Value;
        subscription.CanceledAtUtc = stripeDate(stripeSubscription, "CanceledAt");
        subscription.UpdatedAtUtc = DateTime.UtcNow;
    }

    await db.SaveChangesAsync();
    log.LogInformation("Upserted subscription {SubscriptionId} for user {UserId}", stripeSubscription.Id, userId);
}

// Billing: Sync manual (reconciliação) — tenta buscar no Stripe e fazer upsert
app.MapPost("/api/billing/sync", async (ClaimsPrincipal user, SyncReq req, [FromServices] AppDbContext db, [FromServices] IConfiguration cfg, [FromServices] ILogger<Program> log) =>
{
    var emailFromToken = user.FindFirstValue(ClaimTypes.Email) ?? user.FindFirstValue(JwtRegisteredClaimNames.Email);
    if (string.IsNullOrWhiteSpace(emailFromToken)) return Results.Unauthorized();

    log.LogInformation("/api/billing/sync called by user {Email} with payload: subscriptionId={SubId}, customerId={CustId}, email={Email}", 
        emailFromToken, req.SubscriptionId, req.CustomerId, req.Email);

    // Helpers de mapeamento (mesmos do webhook)
    string? MonthlyPriceId() => Environment.GetEnvironmentVariable("STRIPE_MONTHLY_PRICE_ID") ?? cfg["Stripe:MonthlyPriceId"];
    string? AnnualPriceId() => Environment.GetEnvironmentVariable("STRIPE_ANNUAL_PRICE_ID") ?? cfg["Stripe:AnnualPriceId"];
    SubscriptionPlan MapPlan(string? priceId, string? interval)
    {
        if (!string.IsNullOrWhiteSpace(priceId))
        {
            if (!string.IsNullOrWhiteSpace(MonthlyPriceId()) && priceId == MonthlyPriceId()) return SubscriptionPlan.Monthly;
            if (!string.IsNullOrWhiteSpace(AnnualPriceId()) && priceId == AnnualPriceId()) return SubscriptionPlan.Annual;
        }
        if (!string.IsNullOrWhiteSpace(interval))
        {
            if (string.Equals(interval, "month", StringComparison.OrdinalIgnoreCase)) return SubscriptionPlan.Monthly;
            if (string.Equals(interval, "year", StringComparison.OrdinalIgnoreCase)) return SubscriptionPlan.Annual;
        }
        return SubscriptionPlan.Monthly;
    }
    SubscriptionStatus MapStatus(string? status) => (status ?? string.Empty).ToLowerInvariant() switch
    {
        "incomplete" => SubscriptionStatus.Incomplete,
        "incomplete_expired" => SubscriptionStatus.IncompleteExpired,
        "trialing" => SubscriptionStatus.Trialing,
        "active" => SubscriptionStatus.Active,
        "past_due" => SubscriptionStatus.PastDue,
        "canceled" => SubscriptionStatus.Canceled,
        "unpaid" => SubscriptionStatus.Unpaid,
        _ => SubscriptionStatus.Incomplete
    };

    var subService = new StripeSubscriptionService();
    var custService = new Stripe.CustomerService();
    StripeSubscription? sub = null;

    try
    {
        log.LogInformation("Attempting to find subscription in Stripe...");
        
        if (!string.IsNullOrWhiteSpace(req.SubscriptionId))
        {
            log.LogInformation("Searching by subscription ID: {SubId}", req.SubscriptionId);
            sub = await subService.GetAsync(req.SubscriptionId);
        }
        else if (!string.IsNullOrWhiteSpace(req.CustomerId))
        {
            log.LogInformation("Searching by customer ID: {CustId}", req.CustomerId);
            var list = await subService.ListAsync(new Stripe.SubscriptionListOptions { Customer = req.CustomerId, Limit = 10 });
            sub = list.Data?.FirstOrDefault(s => s.Status == "active" || s.Status == "trialing") ?? list.Data?.FirstOrDefault();
            log.LogInformation("Found {Count} subscriptions for customer, selected: {SubId}", list.Data?.Count ?? 0, sub?.Id);
        }
        else
        {
            var targetEmail = string.IsNullOrWhiteSpace(req.Email) ? emailFromToken : req.Email!.Trim().ToLowerInvariant();
            log.LogInformation("Searching by email: {Email}", targetEmail);
            
            // Estratégia 1: Buscar customers por email
            var custs = await custService.ListAsync(new Stripe.CustomerListOptions { Email = targetEmail, Limit = 10 });
            log.LogInformation("Found {Count} customers for email", custs.Data?.Count ?? 0);
            
            if (custs.Data?.Any() == true)
            {
                // Tenta todos os customers encontrados, priorizando o mais recente
                foreach (var cust in custs.Data.OrderByDescending(c => c.Created))
                {
                    log.LogInformation("Checking customer: {CustId} (created: {Created})", cust.Id, cust.Created);
                    var list = await subService.ListAsync(new Stripe.SubscriptionListOptions { Customer = cust.Id, Limit = 10 });
                    var candidateSub = list.Data?.FirstOrDefault(s => s.Status == "active" || s.Status == "trialing") ?? list.Data?.FirstOrDefault();
                    
                    if (candidateSub != null)
                    {
                        log.LogInformation("Found subscription {SubId} for customer {CustId}", candidateSub.Id, cust.Id);
                        sub = candidateSub;
                        break;
                    }
                }
            }
            
            // Estratégia 2: Se não encontrou, buscar subscriptions recentes (últimas 24h) que podem estar sem customer linkado
            if (sub == null)
            {
                log.LogInformation("No subscription found by email, searching recent subscriptions...");
                var recentCutoff = DateTimeOffset.UtcNow.AddHours(-24);
                
                try
                {
                    var recentSubs = await subService.ListAsync(new Stripe.SubscriptionListOptions 
                    { 
                        Created = new DateRangeOptions { GreaterThanOrEqual = recentCutoff.DateTime },
                        Status = "all",
                        Limit = 50
                    });
                    
                    log.LogInformation("Found {Count} recent subscriptions", recentSubs.Data?.Count ?? 0);
                    
                    // Para cada subscription recente, verifica se o customer tem o email correto
                    foreach (var recentSub in recentSubs.Data?.Where(s => s.Status == "active" || s.Status == "trialing") ?? Enumerable.Empty<StripeSubscription>())
                    {
                        if (!string.IsNullOrWhiteSpace(recentSub.CustomerId))
                        {
                            try
                            {
                                var customer = await custService.GetAsync(recentSub.CustomerId);
                                if (string.Equals(customer.Email, targetEmail, StringComparison.OrdinalIgnoreCase))
                                {
                                    log.LogInformation("Found matching subscription {SubId} via recent search for customer {CustId}", recentSub.Id, customer.Id);
                                    sub = recentSub;
                                    break;
                                }
                            }
                            catch (Exception ex)
                            {
                                log.LogWarning(ex, "Failed to get customer {CustId} for recent subscription {SubId}", recentSub.CustomerId, recentSub.Id);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    log.LogWarning(ex, "Failed to search recent subscriptions");
                }
            }
        }
    }
    catch (Exception ex)
    {
        log.LogError(ex, "/api/billing/sync failed to fetch subscription from Stripe");
        return Results.BadRequest($"Falha ao consultar Stripe: {ex.Message}");
    }

    if (sub == null) 
    {
        log.LogWarning("No subscription found in Stripe for user {Email}", emailFromToken);
        return Results.NotFound("Assinatura não encontrada no Stripe");
    }

    log.LogInformation("Found subscription in Stripe: {SubId}, status: {Status}, customer: {CustId}", sub.Id, sub.Status, sub.CustomerId);

    // Resolve usuário
    var email = emailFromToken;
    if (!string.IsNullOrWhiteSpace(sub.CustomerId))
    {
        try {
            var cust = await custService.GetAsync(sub.CustomerId);
            if (!string.IsNullOrWhiteSpace(cust?.Email)) email = cust.Email;
            log.LogInformation("Resolved email from customer: {Email}", email);
        } catch (Exception ex) {
            log.LogWarning(ex, "Failed to get customer details from Stripe");
        }
    }
    var u = await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Email == email);
    if (u is null) 
    {
        log.LogError("User not found in database: {Email}", email);
        return Results.Unauthorized();
    }

    log.LogInformation("Resolved user: {UserId} ({Email})", u.Id, u.Email);

    // Helper to read Stripe DateTime fields (compat)
    static DateTime? StripeDate(StripeSubscription s, string prop)
    {
        var p = s.GetType().GetProperty(prop);
        var v = p?.GetValue(s);
        if (v is DateTime dt) return dt.ToUniversalTime();
        if (v is long l) return DateTimeOffset.FromUnixTimeSeconds(l).UtcDateTime;
        return null;
    }

    var price = sub.Items?.Data?.FirstOrDefault()?.Price;
    var priceId = price?.Id;
    var interval = price?.Recurring?.Interval;
    var plan = MapPlan(priceId, interval);
    var status = MapStatus(sub.Status);
    DateTime? start = StripeDate(sub, "CurrentPeriodStart");
    DateTime? end = StripeDate(sub, "CurrentPeriodEnd");
    
    log.LogInformation("Subscription details: priceId={PriceId}, interval={Interval}, plan={Plan}, status={Status}, period={Start} to {End}", 
        priceId, interval, plan, status, start, end);
    
    if (start == null || end == null) 
    {
        log.LogError("Subscription missing period dates: start={Start}, end={End}", start, end);
        return Results.BadRequest("Assinatura sem período atual");
    }

    var row = await db.Subscriptions.FirstOrDefaultAsync(s => s.ProviderSubscriptionId == sub.Id);
    if (row == null)
    {
        log.LogInformation("Creating new subscription record");
        var actives = await db.Subscriptions
            .Where(s => s.UserId == u.Id && (s.Status == SubscriptionStatus.Active || s.Status == SubscriptionStatus.Trialing) && s.ProviderSubscriptionId != sub.Id)
            .ToListAsync();
        foreach (var a in actives)
        {
            a.Status = SubscriptionStatus.Canceled;
            a.CanceledAtUtc = DateTime.UtcNow;
            a.UpdatedAtUtc = DateTime.UtcNow;
            log.LogInformation("Canceled existing subscription: {SubId}", a.ProviderSubscriptionId);
        }
        row = new DbSubscription
        {
            Id = Guid.NewGuid(),
            UserId = u.Id,
            Provider = "stripe",
            ProviderCustomerId = sub.CustomerId,
            ProviderSubscriptionId = sub.Id,
            ProviderPriceId = priceId,
            Plan = plan,
            Status = status,
            StartedAtUtc = (status == SubscriptionStatus.Active || status == SubscriptionStatus.Trialing) ? DateTime.UtcNow : null,
            CurrentPeriodStartUtc = start.Value,
            CurrentPeriodEndUtc = end.Value,
            CreatedAtUtc = DateTime.UtcNow,
            UpdatedAtUtc = DateTime.UtcNow
        };
        await db.Subscriptions.AddAsync(row);
    }
    else
    {
        log.LogInformation("Updating existing subscription record");
        row.UserId = u.Id;
        row.ProviderCustomerId = sub.CustomerId;
        row.ProviderPriceId = priceId ?? row.ProviderPriceId;
        row.Plan = plan;
        row.Status = status;
        row.CurrentPeriodStartUtc = start.Value;
        row.CurrentPeriodEndUtc = end.Value;
        row.CanceledAtUtc = StripeDate(sub, "CanceledAt");
        row.UpdatedAtUtc = DateTime.UtcNow;
    }

    await db.SaveChangesAsync();
    log.LogInformation("/api/billing/sync SUCCESS: upserted subId={SubId} userId={UserId} status={Status} plan={Plan}", sub.Id, u.Id, status, plan);
    return Results.Ok(new { ok = true, subId = sub.Id, status = status.ToString().ToLowerInvariant(), plan = plan.ToString().ToLowerInvariant() });
}).RequireAuthorization();

// Debug endpoint to test Stripe connectivity
app.MapGet("/api/billing/debug", async (ClaimsPrincipal user, [FromServices] ILogger<Program> log) =>
{
    var email = user.FindFirstValue(ClaimTypes.Email) ?? user.FindFirstValue(JwtRegisteredClaimNames.Email);
    if (string.IsNullOrWhiteSpace(email)) return Results.Unauthorized();

    try
    {
        log.LogInformation("Debug: Testing Stripe connectivity for user {Email}", email);
        
        var custService = new Stripe.CustomerService();
        var custs = await custService.ListAsync(new Stripe.CustomerListOptions { Email = email, Limit = 5 });
        
        var result = new {
            email = email,
            stripeConnected = true,
            customersFound = custs.Data?.Count ?? 0,
            customers = custs.Data?.Select(c => new {
                id = c.Id,
                email = c.Email,
                created = c.Created
            }).ToList()
        };
        
        log.LogInformation("Debug result: {Result}", System.Text.Json.JsonSerializer.Serialize(result));
        return Results.Ok(result);
    }
    catch (Exception ex)
    {
        log.LogError(ex, "Debug: Stripe connectivity test failed");
        return Results.Ok(new {
            email = email,
            stripeConnected = false,
            error = ex.Message
        });
    }
}).RequireAuthorization();

app.MapPost("/api/assessment", async (ClaimsPrincipal claimsPrincipal, AssessmentDto dto, [FromServices] AppDbContext db) =>
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

app.MapGet("/api/assessment/latest", async (ClaimsPrincipal user, [FromServices] AppDbContext db) =>
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

app.MapMethods("/api/auth/google/callback", new[] { "GET", "POST" }, async (HttpContext ctx, [FromServices] AppDbContext db) =>
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
    try
    {
        
        var email = user.FindFirstValue(ClaimTypes.Email) ?? user.FindFirstValue(JwtRegisteredClaimNames.Email);
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

app.MapGet("/api/goals", async (ClaimsPrincipal user, [FromServices] AppDbContext db, string? period = null, string? startDate = null, string? endDate = null) =>
{
    var email = user.FindFirstValue(ClaimTypes.Email) ?? user.FindFirstValue(JwtRegisteredClaimNames.Email);
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

app.MapPut("/api/goals/{id:guid}", async (ClaimsPrincipal user, Guid id, UpdateGoalDto dto, [FromServices] AppDbContext db) =>
{
    var email = user.FindFirstValue(ClaimTypes.Email) ?? user.FindFirstValue(JwtRegisteredClaimNames.Email);
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

app.MapDelete("/api/goals/{id:guid}", async (ClaimsPrincipal user, Guid id, [FromServices] AppDbContext db) =>
{
    var email = user.FindFirstValue(ClaimTypes.Email) ?? user.FindFirstValue(JwtRegisteredClaimNames.Email);
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

app.Run();

record SignupDto(string Name, string Email, string Password);
record LoginDto(string Email, string Password);
record AssessmentDto(Dictionary<string,int> Scores, double Average, string CreatedAtUtc);
record GoalDto(Guid Id, string Text, bool Done, string Period, string StartDate, string EndDate, string? Category, string CreatedAtUtc);
record CreateGoalDto(string Text, GoalPeriod Period, DateTime StartDate, DateTime EndDate, string? Category);
record UpdateGoalDto(bool Done);
record UpdatePreferencesDto(string? Name, string? BirthDate);
record CheckoutReq(string PriceId, string? SuccessUrl, string? CancelUrl);
record PortalReq(string? ReturnUrl);
record SyncReq(string? SubscriptionId, string? CustomerId, string? Email);
