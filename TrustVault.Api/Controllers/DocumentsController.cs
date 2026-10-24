using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
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

    public DocumentsController(AppDbContext db, IDocumentAuthorizationService authz, IFileStorage storage)
    {
        _db = db;
        _authz = authz;
        _storage = storage;
    }

    // The user id always comes from the authenticated session, never from the request body.
    private Guid CurrentUserId => Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);

    [HttpPost]
    [Authorize(Roles = Roles.Owner)]
    [RequestSizeLimit(12 * 1024 * 1024)]
    public async Task<IActionResult> Upload([FromForm] UploadRequest request, CancellationToken ct)
    {
        var file = request.File;

        var header = new byte[512];
        int headerLength;
        await using (var probe = file.OpenReadStream())
        {
            headerLength = await probe.ReadAsync(header, ct);
        }

        if (!UploadValidator.TryValidate(file.FileName, file.Length, header, headerLength, out var contentType, out var error))
            return BadRequest(new ProblemDetails { Status = 400, Title = error });

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

        _db.Documents.Add(document);
        try
        {
            await _db.SaveChangesAsync(ct);
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
        if (!result.Allowed) return NotFound();
        return Ok(ToDto(result.Granted!.Document));
    }

    [HttpGet("{id:guid}/content")]
    public async Task<IActionResult> Download(Guid id, CancellationToken ct)
    {
        // THE decision point for downloads: no AuthorizedDocument, no file.
        var result = await _authz.AuthorizeAsync(CurrentUserId, id, DocumentAccess.Read, ct);
        if (!result.Allowed) return NotFound();

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

        // Always an attachment with a generic type, so the browser never renders uploaded content.
        return File(stream, "application/octet-stream", result.Granted!.Document.OriginalFileName);
    }

    private static DocumentDto ToDto(Document d) =>
        new(d.Id, d.Title, d.Category, d.OriginalFileName, d.SizeBytes, d.OwnerId, d.CreatedUtc);
}