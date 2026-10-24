using Microsoft.EntityFrameworkCore;
using TrustVault.Api.Data;

namespace TrustVault.Api.Documents;

public enum DocumentAccess
{
    Read,
    Edit,
    Delete,
    ManagePermissions
}

// Proof that the authorisation service approved access to this document.
// The constructor is internal on purpose: only code in this assembly can create one,
// and the only place that does is DocumentAuthorizationService.
public sealed class AuthorizedDocument
{
    public Document Document { get; }
    internal AuthorizedDocument(Document document) => Document = document;
}

public sealed record AuthorizationResult(AuthorizedDocument? Granted, string? DenyReason)
{
    public bool Allowed => Granted is not null;
}

public interface IDocumentAuthorizationService
{
    Task<AuthorizationResult> AuthorizeAsync(Guid userId, Guid documentId, DocumentAccess required, CancellationToken ct = default);
}

public sealed class DocumentAuthorizationService : IDocumentAuthorizationService
{
    private readonly AppDbContext _db;
    public DocumentAuthorizationService(AppDbContext db) => _db = db;

    public async Task<AuthorizationResult> AuthorizeAsync(Guid userId, Guid documentId, DocumentAccess required, CancellationToken ct = default)
    {
        // Soft-deleted documents are treated as if they do not exist.
        var document = await _db.Documents.AsNoTracking()
            .FirstOrDefaultAsync(d => d.Id == documentId && d.DeletedUtc == null, ct);
        if (document is null) return Deny("not_found");

        // The owner may do everything with their own document.
        if (document.OwnerId == userId) return Allow(document);

        // Everyone else needs an ACTIVE grant, looked up fresh on every call (no caching).
        var level = await _db.DocumentPermissions.AsNoTracking()
            .Where(p => p.DocumentId == documentId && p.UserId == userId && p.RevokedUtc == null)
            .Select(p => (DocumentLevel?)p.Level)
            .FirstOrDefaultAsync(ct);
        if (level is null) return Deny("no_grant");

        // Deny by default: anything not listed here is refused.
        return required switch
        {
            DocumentAccess.Read => Allow(document),
            DocumentAccess.Edit => level == DocumentLevel.Edit ? Allow(document) : Deny("insufficient_level"),
            _ => Deny("owner_only")
        };
    }

    private static AuthorizationResult Allow(Document document) => new(new AuthorizedDocument(document), null);
    private static AuthorizationResult Deny(string reason) => new(null, reason);
}