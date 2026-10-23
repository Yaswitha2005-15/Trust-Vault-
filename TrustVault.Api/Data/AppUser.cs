using Microsoft.AspNetCore.Identity;

namespace TrustVault.Api.Data;

public class AppUser : IdentityUser<Guid>
{
    public bool IsActive { get; set; } = true;
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
}