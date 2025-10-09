using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Collections.Generic;
using LifeBalance.Api.Data;
using LifeBalance.Api.Models;
using Stripe;
// Alias para evitar ambiguidade entre tipos do Stripe e tipos internos
using CheckoutSession = Stripe.Checkout.Session;
using CheckoutSessionService = Stripe.Checkout.SessionService;
using CheckoutSessionCreateOptions = Stripe.Checkout.SessionCreateOptions;
using CheckoutLineItemOptions = Stripe.Checkout.SessionLineItemOptions;
using BillingPortalSessionService = Stripe.BillingPortal.SessionService;
using BillingPortalSessionCreateOptions = Stripe.BillingPortal.SessionCreateOptions;
using StripeSubscription = Stripe.Subscription;
using StripeSubscriptionService = Stripe.SubscriptionService;
using DbSubscription = LifeBalance.Api.Models.Subscription;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using LifeBalance.API.Models.Enums;
using LifeBalance.Api.Services;
using LifeBalance.Api.Repositories;
using LifeBalance.Api.Models;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Mvc;

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
app.MapGet("/api/billing/subscription", async (ClaimsPrincipal user, [FromServices] AppDbContext db, [FromServices] ISubscriptionService svc, [FromServices] ILogger<Program> log) =>
{
    var email = user.FindFirstValue(ClaimTypes.Email) ?? user.FindFirstValue(JwtRegisteredClaimNames.Email);
    if (string.IsNullOrWhiteSpace(email)) return Results.Unauthorized();

    var u = await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Email == email);
    if (u is null) return Results.Unauthorized();

    var (active, plan, renewsAtUtc) = await svc.GetStatusAsync(u.Id);
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
    options.CustomerEmail = u.Email;

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

// Billing: Stripe Webhook
app.MapPost("/api/billing/webhook", async (HttpRequest http, [FromServices] AppDbContext db, [FromServices] IConfiguration cfg, [FromServices] ILogger<Program> log) =>
{
    using var reader = new StreamReader(http.Body);
    var json = await reader.ReadToEndAsync();
    var signature = http.Headers["Stripe-Signature"].ToString();
    var webhookSecret = Environment.GetEnvironmentVariable("STRIPE_WEBHOOK_SECRET") ?? cfg["Stripe:WebhookSecret"];
    if (string.IsNullOrWhiteSpace(webhookSecret)) return Results.BadRequest("Webhook secret não configurado");

    Event stripeEvent;
    try {
        stripeEvent = EventUtility.ConstructEvent(json, signature, webhookSecret);
    } catch (Exception ex) {
        log.LogError(ex, "Stripe webhook signature validation failed. HasSig={HasSig} PayloadLen={Len}", !string.IsNullOrWhiteSpace(signature), json?.Length ?? 0);
        return Results.BadRequest();
    }

    log.LogInformation("Stripe webhook event received: type={Type} id={Id}", stripeEvent.Type, stripeEvent.Id);

    string? MonthlyPriceId() => Environment.GetEnvironmentVariable("STRIPE_MONTHLY_PRICE_ID") ?? cfg["Stripe:MonthlyPriceId"];
    string? AnnualPriceId() => Environment.GetEnvironmentVariable("STRIPE_ANNUAL_PRICE_ID") ?? cfg["Stripe:AnnualPriceId"];

    SubscriptionPlan? MapPlan(string? priceId, string? interval)
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
        return null;
    }

    SubscriptionStatus MapStatus(string? status)
    {
        return (status ?? string.Empty).ToLowerInvariant() switch
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
    }

    switch (stripeEvent.Type)
    {
        case "checkout.session.completed":
        {
            var session = stripeEvent.Data.Object as CheckoutSession;
            if (session is null) break;
            log.LogInformation("Event checkout.session.completed: sessionId={SessionId} customer={Customer} subscription={Subscription} clientRef={ClientRef}", session.Id, session.Customer, session.Subscription, session.ClientReferenceId);

            // Resolve user by client_reference_id (can be Guid or email), or by email
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
                    // treat as email
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
            log.LogInformation("Resolved userId={UserId} from checkout.session.completed", userId);

            // Helper to read Stripe DateTime fields (compat across SDKs)
            static DateTime? StripeDate(StripeSubscription s, string prop)
            {
                var p = s.GetType().GetProperty(prop);
                var v = p?.GetValue(s);
                if (v is DateTime dt) return dt.ToUniversalTime();
                if (v is long l) return DateTimeOffset.FromUnixTimeSeconds(l).UtcDateTime;
                return null;
            }

            // If we have a subscription id from the session, fetch and upsert now
            var subId = session.SubscriptionId;
            if (!string.IsNullOrWhiteSpace(subId))
            {
                try
                {
                    var subsService = new StripeSubscriptionService();
                    var sub = await subsService.GetAsync(subId);
                    var price = sub.Items?.Data?.FirstOrDefault()?.Price;
                    var priceId = price?.Id;
                    var interval = price?.Recurring?.Interval;
                    var plan = MapPlan(priceId, interval) ?? SubscriptionPlan.Monthly;
                    var status = MapStatus(sub.Status);

                    DateTime? start = StripeDate(sub, "CurrentPeriodStart");
                    DateTime? end = StripeDate(sub, "CurrentPeriodEnd");
                    log.LogInformation("Fetched sub from session: subId={SubId} customer={CustomerId} status={Status} priceId={PriceId} interval={Interval} plan={Plan} start={Start} end={End}", sub.Id, sub.CustomerId, sub.Status, priceId, interval, plan, start, end);
                    if (start != null && end != null)
                    {
                        var row = await db.Subscriptions.FirstOrDefaultAsync(s => s.ProviderSubscriptionId == sub.Id);
                        if (row == null)
                        {
                            if (userId != Guid.Empty)
                            {
                                var actives = await db.Subscriptions
                                    .Where(s => s.UserId == userId && (s.Status == SubscriptionStatus.Active || s.Status == SubscriptionStatus.Trialing) && s.ProviderSubscriptionId != sub.Id)
                                    .ToListAsync();
                                foreach (var a in actives)
                                {
                                    a.Status = SubscriptionStatus.Canceled;
                                    a.CanceledAtUtc = DateTime.UtcNow;
                                    a.UpdatedAtUtc = DateTime.UtcNow;
                                }
                            }
                            row = new DbSubscription
                            {
                                Id = Guid.NewGuid(),
                                UserId = userId,
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
                            log.LogInformation("Inserted subscription row for subId={SubId} userId={UserId}", sub.Id, userId);
                        }
                        else
                        {
                            if (userId != Guid.Empty) row.UserId = userId;
                            row.ProviderCustomerId = sub.CustomerId;
                            row.ProviderPriceId = priceId ?? row.ProviderPriceId;
                            row.Plan = plan;
                            row.Status = status;
                            row.CurrentPeriodStartUtc = start.Value;
                            row.CurrentPeriodEndUtc = end.Value;
                            row.CanceledAtUtc = StripeDate(sub, "CanceledAt");
                            row.UpdatedAtUtc = DateTime.UtcNow;
                            log.LogInformation("Updated subscription row for subId={SubId} userId={UserId}", sub.Id, userId);
                        }
                        await db.SaveChangesAsync();
                    }
                }
                catch (Exception ex) { log.LogError(ex, "Failed to upsert subscription from checkout.session.completed subId={SubId}", subId); }
            }
            break;
        }

        case "customer.subscription.created":
        case "customer.subscription.updated":
        case "customer.subscription.deleted":
        {
            var sub = stripeEvent.Data.Object as StripeSubscription;
            if (sub is null) break;

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
            var plan = MapPlan(priceId, interval) ?? SubscriptionPlan.Monthly;
            var status = MapStatus(sub.Status);
            log.LogInformation("Event {Type}: subId={SubId} customer={CustomerId} stripeStatus={StripeStatus} mappedStatus={Status} priceId={PriceId} interval={Interval} plan={Plan}", stripeEvent.Type, sub.Id, sub.CustomerId, sub.Status, status, priceId, interval, plan);

            DateTime? start = StripeDate(sub, "CurrentPeriodStart");
            DateTime? end = StripeDate(sub, "CurrentPeriodEnd");

            // Try to resolve user
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
                try {
                    var cs = new CustomerService();
                    var cust = await cs.GetAsync(sub.CustomerId);
                    var email = cust?.Email;
                    if (!string.IsNullOrWhiteSpace(email))
                    {
                        var u = await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Email == email);
                        if (u != null) userId = u.Id;
                    }
                } catch { }
            }

            if (start == null || end == null)
            {
                // If period missing, don't persist inconsistent row
                break;
            }

            // Upsert subscription row
            var row = await db.Subscriptions.FirstOrDefaultAsync(s => s.ProviderSubscriptionId == sub.Id);
            if (row == null)
            {
                // Ensure uniqueness: only one Active/Trialing per user
                if (userId != Guid.Empty)
                {
                    var actives = await db.Subscriptions
                        .Where(s => s.UserId == userId && (s.Status == SubscriptionStatus.Active || s.Status == SubscriptionStatus.Trialing) && s.ProviderSubscriptionId != sub.Id)
                        .ToListAsync();
                    foreach (var a in actives)
                    {
                        a.Status = SubscriptionStatus.Canceled;
                        a.CanceledAtUtc = DateTime.UtcNow;
                        a.UpdatedAtUtc = DateTime.UtcNow;
                    }
                }
                row = new DbSubscription
                {
                    Id = Guid.NewGuid(),
                    UserId = userId,
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
                if (userId != Guid.Empty) row.UserId = userId;
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
            log.LogInformation("Upserted subscription row from {Type} for subId={SubId} userId={UserId}", stripeEvent.Type, sub.Id, userId);
            break;
        }
        default:
            log.LogInformation("Unhandled Stripe event type={Type}", stripeEvent.Type);
            break;
    }

    return Results.Ok();
});

// Billing: Sync manual (reconciliação) — tenta buscar no Stripe e fazer upsert
app.MapPost("/api/billing/sync", async (ClaimsPrincipal user, SyncReq req, [FromServices] AppDbContext db, [FromServices] IConfiguration cfg, [FromServices] ILogger<Program> log) =>
{
    var emailFromToken = user.FindFirstValue(ClaimTypes.Email) ?? user.FindFirstValue(JwtRegisteredClaimNames.Email);
    if (string.IsNullOrWhiteSpace(emailFromToken)) return Results.Unauthorized();

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
        if (!string.IsNullOrWhiteSpace(req.SubscriptionId))
        {
            sub = await subService.GetAsync(req.SubscriptionId);
        }
        else if (!string.IsNullOrWhiteSpace(req.CustomerId))
        {
            var list = await subService.ListAsync(new Stripe.SubscriptionListOptions { Customer = req.CustomerId, Limit = 1 });
            sub = list.Data?.FirstOrDefault();
        }
        else
        {
            var targetEmail = string.IsNullOrWhiteSpace(req.Email) ? emailFromToken : req.Email!.Trim().ToLowerInvariant();
            // Tenta localizar customer por e-mail
            var custs = await custService.ListAsync(new Stripe.CustomerListOptions { Email = targetEmail, Limit = 1 });
            var cust = custs.Data?.FirstOrDefault();
            if (cust != null)
            {
                var list = await subService.ListAsync(new Stripe.SubscriptionListOptions { Customer = cust.Id, Limit = 1 });
                sub = list.Data?.FirstOrDefault();
            }
        }
    }
    catch (Exception ex)
    {
        log.LogError(ex, "/api/billing/sync failed to fetch subscription from Stripe");
        return Results.BadRequest("Falha ao consultar Stripe");
    }

    if (sub == null) return Results.NotFound("Assinatura não encontrada no Stripe");

    // Resolve usuário
    var email = emailFromToken;
    if (!string.IsNullOrWhiteSpace(sub.CustomerId))
    {
        try {
            var cust = await custService.GetAsync(sub.CustomerId);
            if (!string.IsNullOrWhiteSpace(cust?.Email)) email = cust.Email;
        } catch { }
    }
    var u = await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Email == email);
    if (u is null) return Results.Unauthorized();

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
    if (start == null || end == null) return Results.BadRequest("Assinatura sem período atual");

    var row = await db.Subscriptions.FirstOrDefaultAsync(s => s.ProviderSubscriptionId == sub.Id);
    if (row == null)
    {
        var actives = await db.Subscriptions
            .Where(s => s.UserId == u.Id && (s.Status == SubscriptionStatus.Active || s.Status == SubscriptionStatus.Trialing) && s.ProviderSubscriptionId != sub.Id)
            .ToListAsync();
        foreach (var a in actives)
        {
            a.Status = SubscriptionStatus.Canceled;
            a.CanceledAtUtc = DateTime.UtcNow;
            a.UpdatedAtUtc = DateTime.UtcNow;
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
    log.LogInformation("/api/billing/sync upserted subId={SubId} userId={UserId} status={Status}", sub.Id, u.Id, status);
    return Results.Ok(new { ok = true, subId = sub.Id, status = status.ToString().ToLowerInvariant(), plan = plan.ToString().ToLowerInvariant() });
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
