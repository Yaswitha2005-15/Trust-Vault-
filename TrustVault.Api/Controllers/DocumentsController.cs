using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
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

public record DocumentDto(Guid Id, string Title, string? Category, string OriginalFileName,
    long SizeBytes, Guid OwnerId, DateTime CreatedUtc);

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

    private static DocumentDto ToDto(Document d) =>
        new(d.Id, d.Title, d.Category, d.OriginalFileName, d.SizeBytes, d.OwnerId, d.CreatedUtc);
}