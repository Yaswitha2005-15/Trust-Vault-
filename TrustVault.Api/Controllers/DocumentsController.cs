using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TrustVault.Api.Audit;
using TrustVault.Api.Data;
using TrustVault.Api.Documents;

namespace TrustVault.Api.Controllers;

public class UploadRequest
{
    [Required]
    public IFormFile File { get; set; } = null!;

    [Required, MaxLength(200)]
    public string Title { get; set; } = "";

    [MaxLength(100)]
    public string? Category { get; set; }
}

public class UpdateDocumentRequest
{
    [Required, MaxLength(200)]
    public string Title { get; set; } = "";

    [MaxLength(100)]
    public string? Category { get; set; }
}

public record DocumentDto(Guid Id, string Title, string? Category, string OriginalFileName,
    long SizeBytes, Guid OwnerId, DateTime CreatedUtc);

public record DocumentListItem(Guid Id, string Title, string? Category, string OriginalFileName,
    long SizeBytes, string OwnerEmail, DateTime CreatedUtc, bool IsOwner);

[ApiController]
[Route("api/documents")]
[Authorize]
public class DocumentsController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly IDocumentAuthorizationService _authz;
    private readonly IFileStorage _storage;
    private readonly IAuditService _audit;
    private readonly ILogger<DocumentsController> _logger;

    public DocumentsController(AppDbContext db, IDocumentAuthorizationService authz, IFileStorage storage,
        IAuditService audit, ILogger<DocumentsController> logger)
    {
        _db = db;
        _authz = authz;
        _storage = storage;
        _audit = audit;
        _logger = logger;
    }

    // The user id always comes from the authenticated session, never from the request body.
    private Guid CurrentUserId => Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);

    // Denials are always enforced. If recording one fails, access is still denied and the failure is logged.
    private async Task AuditDeniedAsync(string action, Guid? documentId, string reason)
    {
        try
        {
            await _audit.RecordAsync(CurrentUserId, action, documentId, AuditOutcome.Denied, reason, CancellationToken.None);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Could not write audit record for denied {Action}", action);
        }
    }

    // Someone who can already read the document knows it exists, so "not allowed" is a 403.
    // Everyone else gets the same 404 as a document that does not exist.
    private IActionResult DeniedResult(string? reason) =>
        reason is "owner_only" or "insufficient_level"
            ? StatusCode(StatusCodes.Status403Forbidden)
            : NotFound();

    [HttpPost]
    [RequestSizeLimit(12 * 1024 * 1024)]
    public async Task<IActionResult> Upload([FromForm] UploadRequest request, CancellationToken ct)
    {
        if (!User.IsInRole(Roles.Owner))
        {
            await AuditDeniedAsync("document.upload", null, "role_not_allowed");
            return StatusCode(StatusCodes.Status403Forbidden);
        }

        var file = request.File;

        var header = new byte[512];
        int headerLength;
        await using (var probe = file.OpenReadStream())
        {
            headerLength = await probe.ReadAsync(header, ct);
        }

        if (!UploadValidator.TryValidate(file.FileName, file.Length, header, headerLength, out var contentType, out var error))
        {
            await AuditDeniedAsync("document.upload", null, "invalid_file");
            return BadRequest(new ProblemDetails { Status = 400, Title = error });
        }

        StoredFile stored;
        await using (var input = file.OpenReadStream())
        {
            stored = await _storage.SaveAsync(input, ct);
        }

        var now = DateTime.UtcNow;
        var document = new Document
        {
            Id = Guid.NewGuid(),
            OwnerId = CurrentUserId,
            Title = request.Title.Trim(),
            Category = string.IsNullOrWhiteSpace(request.Category) ? null : request.Category.Trim(),
            OriginalFileName = UploadValidator.SanitizeFileName(file.FileName),
            StoredFileId = stored.Id,
            ContentType = contentType,
            SizeBytes = stored.SizeBytes,
            Sha256 = stored.Sha256,
            CreatedUtc = now,
            UpdatedUtc = now
        };

        // Fail closed: the document row and its audit row commit together or not at all.
        try
        {
            await using var tx = await _db.Database.BeginTransactionAsync(ct);
            _db.Documents.Add(document);
            await _db.SaveChangesAsync(ct);
            await _audit.RecordAsync(CurrentUserId, "document.upload", document.Id, AuditOutcome.Success, null, ct);
            await tx.CommitAsync(ct);
        }
        catch
        {
            _storage.Delete(stored.Id); // do not leave an orphaned file behind
            throw;
        }

        return CreatedAtAction(nameof(GetMetadata), new { id = document.Id }, ToDto(document));
    }

    // Search and list. The access filter is part of the query itself, so a document the caller
    // cannot read can never appear in the results, the count, or the paging.
    [HttpGet]
    public async Task<IActionResult> Search([FromQuery] string? q, [FromQuery] string? owner,
        [FromQuery] string? category, [FromQuery] DateTime? from, [FromQuery] DateTime? to, CancellationToken ct)
    {
        if ((q?.Length ?? 0) > 100 || (owner?.Length ?? 0) > 256 || (category?.Length ?? 0) > 100)
            return BadRequest(new ProblemDetails { Status = 400, Title = "Search text is too long." });

        var userId = CurrentUserId;

        var query =
            from d in _db.Documents.AsNoTracking()
            join u in _db.Users.AsNoTracking() on d.OwnerId equals u.Id
            where d.DeletedUtc == null
                && (d.OwnerId == userId
                    || _db.DocumentPermissions.Any(p => p.DocumentId == d.Id && p.UserId == userId && p.RevokedUtc == null))
            select new { Document = d, OwnerEmail = u.Email };

        if (!string.IsNullOrWhiteSpace(q))
        {
            var term = q.Trim().ToLower();
            query = query.Where(x => x.Document.Title.ToLower().Contains(term));
        }

        if (!string.IsNullOrWhiteSpace(owner))
        {
            var ownerTerm = owner.Trim().ToLower();
            query = query.Where(x => (x.OwnerEmail ?? "").ToLower().Contains(ownerTerm));
        }

        if (!string.IsNullOrWhiteSpace(category))
        {
            var cat = category.Trim().ToLower();
            query = query.Where(x => x.Document.Category != null && x.Document.Category.ToLower() == cat);
        }

        if (from is not null)
        {
            var start = DateTime.SpecifyKind(from.Value.Date, DateTimeKind.Utc);
            query = query.Where(x => x.Document.CreatedUtc >= start);
        }

        if (to is not null)
        {
            var end = DateTime.SpecifyKind(to.Value.Date.AddDays(1), DateTimeKind.Utc);
            query = query.Where(x => x.Document.CreatedUtc < end);
        }

        var items = await query
            .OrderByDescending(x => x.Document.CreatedUtc)
            .Take(100)
            .Select(x => new DocumentListItem(x.Document.Id, x.Document.Title, x.Document.Category,
                x.Document.OriginalFileName, x.Document.SizeBytes, x.OwnerEmail ?? "",
                x.Document.CreatedUtc, x.Document.OwnerId == userId))
            .ToListAsync(ct);

        return Ok(items);
    }

    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetMetadata(Guid id, CancellationToken ct)
    {
        var result = await _authz.AuthorizeAsync(CurrentUserId, id, DocumentAccess.Read, ct);
        if (!result.Allowed)
        {
            await AuditDeniedAsync("document.view", id, result.DenyReason ?? "denied");
            return NotFound();
        }

        await _audit.RecordAsync(CurrentUserId, "document.view", id, AuditOutcome.Success, null, ct);
        return Ok(ToDto(result.Granted!.Document));
    }

    [HttpGet("{id:guid}/content")]
    public async Task<IActionResult> Download(Guid id, CancellationToken ct)
    {
        // THE decision point for downloads: no AuthorizedDocument, no file.
        var result = await _authz.AuthorizeAsync(CurrentUserId, id, DocumentAccess.Read, ct);
        if (!result.Allowed)
        {
            await AuditDeniedAsync("document.download", id, result.DenyReason ?? "denied");
            return NotFound();
        }

        Response.Headers["X-Content-Type-Options"] = "nosniff";
        Response.Headers["Cache-Control"] = "no-store";

        Stream stream;
        try
        {
            stream = _storage.OpenRead(result.Granted!);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return NotFound();
        }

        // Fail closed: if the download cannot be recorded, the bytes are not sent.
        try
        {
            await _audit.RecordAsync(CurrentUserId, "document.download", id, AuditOutcome.Success, null, ct);
        }
        catch
        {
            await stream.DisposeAsync();
            throw;
        }

        // Always an attachment with a generic type, so the browser never renders uploaded content.
        return File(stream, "application/octet-stream", result.Granted!.Document.OriginalFileName);
    }

    // Edit metadata. Needs the Edit level (or ownership).
    [HttpPut("{id:guid}")]
    public async Task<IActionResult> Update(Guid id, [FromBody] UpdateDocumentRequest request, CancellationToken ct)
    {
        var result = await _authz.AuthorizeAsync(CurrentUserId, id, DocumentAccess.Edit, ct);
        if (!result.Allowed)
        {
            await AuditDeniedAsync("document.edit", id, result.DenyReason ?? "denied");
            return DeniedResult(result.DenyReason);
        }

        // Fail closed: the change and its audit row commit together or not at all.
        await using var tx = await _db.Database.BeginTransactionAsync(ct);

        var document = await _db.Documents.FirstOrDefaultAsync(d => d.Id == id && d.DeletedUtc == null, ct);
        if (document is null) return NotFound();

        document.Title = request.Title.Trim();
        document.Category = string.IsNullOrWhiteSpace(request.Category) ? null : request.Category.Trim();
        document.UpdatedUtc = DateTime.UtcNow;
        await _db.SaveChangesAsync(ct);

        await _audit.RecordAsync(CurrentUserId, "document.edit", id, AuditOutcome.Success, null, ct);
        await tx.CommitAsync(ct);

        return Ok(ToDto(document));
    }

    // Delete. Owner only. Access ends at once (deleted documents are invisible to the authorisation
    // service), all grants are closed, and the stored bytes are removed.
    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var result = await _authz.AuthorizeAsync(CurrentUserId, id, DocumentAccess.Delete, ct);
        if (!result.Allowed)
        {
            await AuditDeniedAsync("document.delete", id, result.DenyReason ?? "denied");
            return DeniedResult(result.DenyReason);
        }

        Guid storedFileId;
        await using (var tx = await _db.Database.BeginTransactionAsync(ct))
        {
            var document = await _db.Documents.FirstOrDefaultAsync(d => d.Id == id && d.DeletedUtc == null, ct);
            if (document is null) return NotFound();

            var now = DateTime.UtcNow;
            document.DeletedUtc = now;
            document.UpdatedUtc = now;

            var grants = await _db.DocumentPermissions
                .Where(p => p.DocumentId == id && p.RevokedUtc == null)
                .ToListAsync(ct);
            foreach (var grant in grants) grant.RevokedUtc = now;

            await _db.SaveChangesAsync(ct);
            await _audit.RecordAsync(CurrentUserId, "document.delete", id, AuditOutcome.Success, null, ct);
            await tx.CommitAsync(ct);

            storedFileId = document.StoredFileId;
        }

        // After the commit: remove the bytes. If this fails the document is still gone for users,
        // and the leftover file is only an orphan (logged, to be cleaned up later).
        try
        {
            _storage.Delete(storedFileId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Document {DocumentId} was deleted but its stored file could not be removed", id);
        }

        return NoContent();
    }

    private static DocumentDto ToDto(Document d) =>
        new(d.Id, d.Title, d.Category, d.OriginalFileName, d.SizeBytes, d.OwnerId, d.CreatedUtc);
}