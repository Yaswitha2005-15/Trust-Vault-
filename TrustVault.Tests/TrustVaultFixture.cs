using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Testcontainers.PostgreSql;
using TrustVault.Api.Data;
using TrustVault.Api.Documents;
using Xunit;

namespace TrustVault.Tests;

public class TrustVaultFixture : IAsyncLifetime
{
    public const string DemoPassword = "Test-Password-12345!";

    private readonly PostgreSqlContainer _db = new PostgreSqlBuilder("postgres:16").Build();
    private readonly string _storageRoot = Path.Combine(Path.GetTempPath(), "trustvault-tests-" + Guid.NewGuid().ToString("N"));
    private WebApplicationFactory<Program> _factory = null!;

    public async Task InitializeAsync()
    {
        await _db.StartAsync();

        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            // "Testing" means user-secrets are NOT loaded, so tests can never touch your dev database.
            builder.UseEnvironment("Testing");
            builder.ConfigureAppConfiguration((_, config) =>
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:Default"] = _db.GetConnectionString(),
                    ["Storage:Root"] = _storageRoot
                }));
        });

        using var scope = _factory.Services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        await context.Database.MigrateAsync();
        await DbSeeder.SeedAsync(scope.ServiceProvider, DemoPassword);
    }

    public async Task DisposeAsync()
    {
        if (_factory is not null) await _factory.DisposeAsync();
        await _db.DisposeAsync();
        try { if (Directory.Exists(_storageRoot)) Directory.Delete(_storageRoot, true); } catch { }
    }

    // https base address, because the auth cookie is Secure outside Development.
    public HttpClient CreateClient() =>
        _factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost") });

    public async Task<AppUser> CreateUserAsync(string email, string role)
    {
        using var scope = _factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<AppUser>>();
        var user = new AppUser { Id = Guid.NewGuid(), UserName = email, Email = email, EmailConfirmed = true };
        var result = await users.CreateAsync(user, DemoPassword);
        if (!result.Succeeded)
            throw new InvalidOperationException(string.Join("; ", result.Errors.Select(e => e.Description)));
        await users.AddToRoleAsync(user, role);
        return user;
    }

    public async Task SetActiveAsync(Guid userId, bool isActive)
    {
        using var scope = _factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<AppUser>>();
        var user = await users.FindByIdAsync(userId.ToString())
            ?? throw new InvalidOperationException("User not found.");
        user.IsActive = isActive;
        var result = await users.UpdateAsync(user);
        if (!result.Succeeded)
            throw new InvalidOperationException(string.Join("; ", result.Errors.Select(e => e.Description)));
    }

    // Temporary helpers: the grant/revoke endpoints come in a later milestone.
    public async Task GrantAsync(Guid documentId, Guid userId, DocumentLevel level, Guid grantedBy)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        db.DocumentPermissions.Add(new DocumentPermission
        {
            Id = Guid.NewGuid(),
            DocumentId = documentId,
            UserId = userId,
            Level = level,
            GrantedByUserId = grantedBy,
            GrantedUtc = DateTime.UtcNow
        });
        await db.SaveChangesAsync();
    }

    public async Task RevokeAsync(Guid documentId, Guid userId)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var grants = await db.DocumentPermissions
            .Where(p => p.DocumentId == documentId && p.UserId == userId && p.RevokedUtc == null)
            .ToListAsync();
        foreach (var grant in grants) grant.RevokedUtc = DateTime.UtcNow;
        await db.SaveChangesAsync();
    }
}

[CollectionDefinition("api")]
public class ApiCollection : ICollectionFixture<TrustVaultFixture> { }