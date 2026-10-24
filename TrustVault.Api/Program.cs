using Microsoft.AspNetCore.Identity;
using TrustVault.Api.Audit;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TrustVault.Api.Data;
using TrustVault.Api.Documents;

var builder = WebApplication.CreateBuilder(args);

// Cookies are Secure everywhere except Development, unless Security:AllowHttpCookies is set.
// That flag exists only so the Docker Compose demo works on plain http://localhost.
// A real deployment sits behind HTTPS and leaves it off.
var cookieSecurePolicy = builder.Environment.IsDevelopment() || builder.Configuration.GetValue<bool>("Security:AllowHttpCookies")
    ? CookieSecurePolicy.SameAsRequest
    : CookieSecurePolicy.Always;

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("Default")));

builder.Services.AddIdentity<AppUser, IdentityRole<Guid>>(options =>
{
    options.Password.RequiredLength = 12;
    options.User.RequireUniqueEmail = true;
    options.Lockout.AllowedForNewUsers = true;
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
})
.AddEntityFrameworkStores<AppDbContext>();

// Re-check the security stamp on EVERY request (default is every 30 minutes),
// so role changes and deactivation take effect immediately.
builder.Services.Configure<SecurityStampValidatorOptions>(o => o.ValidationInterval = TimeSpan.Zero);

builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.Name = "tv.auth";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.SecurePolicy = cookieSecurePolicy;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
    options.SlidingExpiration = true;
    // This is an API: answer 401/403 instead of redirecting to a login page.
    options.Events.OnRedirectToLogin = ctx => { ctx.Response.StatusCode = StatusCodes.Status401Unauthorized; return Task.CompletedTask; };
    options.Events.OnRedirectToAccessDenied = ctx => { ctx.Response.StatusCode = StatusCodes.Status403Forbidden; return Task.CompletedTask; };

    // Keep Identity's security-stamp check, then also require the account to still be active.
    var securityStampCheck = options.Events.OnValidatePrincipal;
    options.Events.OnValidatePrincipal = async context =>
    {
        if (securityStampCheck is not null) await securityStampCheck(context);
        if (context.Principal is null) return;

        var users = context.HttpContext.RequestServices.GetRequiredService<UserManager<AppUser>>();
        var user = await users.GetUserAsync(context.Principal);
        if (user is null || !user.IsActive)
        {
            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
        }
    };
});

builder.Services.AddAntiforgery(o =>
{
    o.HeaderName = "X-XSRF-TOKEN";
    o.Cookie.Name = "tv.antiforgery";
    o.Cookie.HttpOnly = true;
    o.Cookie.SameSite = SameSiteMode.Lax;
    o.Cookie.SecurePolicy = cookieSecurePolicy;
});

// Every POST/PUT/PATCH/DELETE in every controller must carry a valid CSRF token.
// CHANGED: AddControllers -> AddControllersWithViews (registers the services the antiforgery filter needs)
builder.Services.AddControllersWithViews(o => o.Filters.Add(new AutoValidateAntiforgeryTokenAttribute()));
builder.Services.AddAuthorization();
builder.Services.AddScoped<IDocumentAuthorizationService, DocumentAuthorizationService>();
builder.Services.AddSingleton<IFileStorage>(sp =>
{
    var config = sp.GetRequiredService<IConfiguration>();
    var env = sp.GetRequiredService<IWebHostEnvironment>();
    return new LocalFileStorage(config["Storage:Root"] ?? Path.Combine(env.ContentRootPath, "storage"));
});
builder.Services.AddScoped<IAuditService, AuditService>();

var app = builder.Build();

// Applies pending migrations only when asked: dotnet TrustVault.Api.dll --migrate --seed
if (args.Contains("--migrate"))
{
    using var migrateScope = app.Services.CreateScope();
    await migrateScope.ServiceProvider.GetRequiredService<AppDbContext>().Database.MigrateAsync();
}

// Seeding only runs when asked: dotnet run --project TrustVault.Api -- --seed
if (args.Contains("--seed"))
{
    var demoPassword = builder.Configuration["Seed:DemoPassword"]
        ?? throw new InvalidOperationException("Seed:DemoPassword is not configured.");
    using var scope = app.Services.CreateScope();
    await DbSeeder.SeedAsync(scope.ServiceProvider, demoPassword);
}

app.UseMiddleware<TrustVault.Api.SecurityHeadersMiddleware>();
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();

public partial class Program { }