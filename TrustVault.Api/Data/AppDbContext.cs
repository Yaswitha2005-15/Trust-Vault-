using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using TrustVault.Api.Documents;

namespace TrustVault.Api.Data;

public class AppDbContext : IdentityDbContext<AppUser, IdentityRole<Guid>, Guid>
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<Document> Documents => Set<Document>();
    public DbSet<DocumentPermission> DocumentPermissions => Set<DocumentPermission>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<Document>(e =>
        {
            e.Property(x => x.Title).HasMaxLength(200).IsRequired();
            e.Property(x => x.Category).HasMaxLength(100);
            e.Property(x => x.OriginalFileName).HasMaxLength(255).IsRequired();
            e.Property(x => x.ContentType).HasMaxLength(100).IsRequired();
            e.Property(x => x.Sha256).HasMaxLength(64).IsRequired();
            e.HasIndex(x => x.OwnerId);
            e.HasIndex(x => x.Category);
            e.HasIndex(x => x.CreatedUtc);
            e.HasOne<AppUser>().WithMany().HasForeignKey(x => x.OwnerId).OnDelete(DeleteBehavior.Restrict);
        });

        builder.Entity<DocumentPermission>(e =>
        {
            e.Property(x => x.Level).HasConversion<int>();
            e.HasIndex(x => x.UserId);
            // At most ONE active grant per user per document, even under concurrent requests.
            e.HasIndex(x => new { x.DocumentId, x.UserId }).IsUnique().HasFilter("\"RevokedUtc\" IS NULL");
            e.HasOne<Document>().WithMany().HasForeignKey(x => x.DocumentId).OnDelete(DeleteBehavior.Restrict);
            e.HasOne<AppUser>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Restrict);
        });
    }
}