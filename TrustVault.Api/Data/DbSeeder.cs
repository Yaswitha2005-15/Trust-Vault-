using Microsoft.AspNetCore.Identity;

namespace TrustVault.Api.Data;

public static class DbSeeder
{
    public static async Task SeedAsync(IServiceProvider services, string demoPassword)
    {
        var roleManager = services.GetRequiredService<RoleManager<IdentityRole<Guid>>>();
        var userManager = services.GetRequiredService<UserManager<AppUser>>();

        foreach (var role in new[] { Roles.Administrator, Roles.Owner, Roles.Viewer })
        {
            if (!await roleManager.RoleExistsAsync(role))
                await roleManager.CreateAsync(new IdentityRole<Guid>(role));
        }

        await EnsureUserAsync(userManager, "admin@trustvault.local", Roles.Administrator, demoPassword);
        await EnsureUserAsync(userManager, "owner@trustvault.local", Roles.Owner, demoPassword);
        await EnsureUserAsync(userManager, "viewer@trustvault.local", Roles.Viewer, demoPassword);
    }

    private static async Task EnsureUserAsync(UserManager<AppUser> userManager, string email, string role, string password)
    {
        if (await userManager.FindByEmailAsync(email) is not null) return;

        var user = new AppUser { Id = Guid.NewGuid(), UserName = email, Email = email, EmailConfirmed = true };
        var result = await userManager.CreateAsync(user, password);
        if (!result.Succeeded)
            throw new InvalidOperationException("Seeding failed: " + string.Join("; ", result.Errors.Select(e => e.Description)));

        await userManager.AddToRoleAsync(user, role);
    }
}