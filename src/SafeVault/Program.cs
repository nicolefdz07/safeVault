using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Data;
using SafeVault.Services;

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("Default") ?? "Data Source=safevault.db";
var issuer = builder.Configuration["Jwt:Issuer"] ?? "SafeVault";
var audience = builder.Configuration["Jwt:Audience"] ?? "SafeVaultClients";

// The signing key is NEVER stored in source control: set Jwt__Key (env var) or user-secrets.
var jwtKey = builder.Configuration["Jwt:Key"];
if (string.IsNullOrWhiteSpace(jwtKey))
{
    if (!builder.Environment.IsDevelopment())
        throw new InvalidOperationException("Jwt:Key must be configured outside Development.");
    jwtKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48)); // dev-only, random per run
}
if (Encoding.UTF8.GetBytes(jwtKey).Length < 32)
    throw new InvalidOperationException("Jwt:Key must be at least 32 bytes.");

builder.Services.AddSingleton(new UserRepository(connectionString));
builder.Services.AddSingleton(new TokenService(jwtKey, issuer, audience));
builder.Services.AddControllers();

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.MapInboundClaims = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
            ClockSkew = TimeSpan.FromMinutes(1),
            NameClaimType = "name",
            RoleClaimType = "role"
        };
    });
builder.Services.AddAuthorization();

// Brute-force protection on register/login.
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    o.AddFixedWindowLimiter("auth", l =>
    {
        l.PermitLimit = builder.Configuration.GetValue<int?>("RateLimit:AuthPerMinute") ?? 30;
        l.Window = TimeSpan.FromMinutes(1);
        l.QueueLimit = 0;
    });
});

var app = builder.Build();

var repository = app.Services.GetRequiredService<UserRepository>();
repository.Initialize();

// Optional admin seeding from configuration (Seed__AdminPassword). No default password exists.
var adminPassword = builder.Configuration["Seed:AdminPassword"];
if (!string.IsNullOrEmpty(adminPassword) && repository.FindByUsername("admin") is null)
{
    repository.Create(new User(0, "admin", "admin@safevault.local", PasswordService.Hash(adminPassword), Roles.Admin));
}

app.Use(async (context, next) =>
{
    var h = context.Response.Headers;
    h["Content-Security-Policy"] =
        "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";
    h["X-Content-Type-Options"] = "nosniff";
    h["X-Frame-Options"] = "DENY";
    h["Referrer-Policy"] = "no-referrer";
    await next();
});

if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
    app.UseHttpsRedirection();
}

app.UseDefaultFiles();
app.UseStaticFiles();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();

public partial class Program { } // makes Program visible to WebApplicationFactory in tests
