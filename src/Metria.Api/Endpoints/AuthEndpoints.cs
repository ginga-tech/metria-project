using Metria.Api.Contracts;
using Metria.Api.Data;
using Metria.Api.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Metria.Api.Endpoints;

public static class AuthEndpoints
{
    public static WebApplication MapAuthEndpoints(this WebApplication app, IConfiguration config, SymmetricSecurityKey key)
    {
        const string Tag = "Auth";
        var auth = app.MapGroup("/api/auth").WithTags(Tag);

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
        
        auth.MapPost("/signup", async (SignupDto dto, [FromServices] AppDbContext db) =>
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
        }).WithTags(Tag);
        
        auth.MapPost("/login", async (LoginDto dto, [FromServices] AppDbContext db) =>
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
        }).WithTags(Tag);
        

        auth.MapGet("/google/start", (HttpContext ctx) =>
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
        }).WithTags(Tag);
        
        auth.MapMethods("/google/callback", new[] { "GET", "POST" }, async (HttpContext ctx, [FromServices] AppDbContext db) =>
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
        }).WithTags(Tag);
        

        return app;
    }
}



