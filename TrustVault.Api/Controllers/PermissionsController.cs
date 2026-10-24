using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TrustVault.Api.Audit;
using TrustVault.Api.Data;
using TrustVault.Api.Documents;

namespace TrustVault.Api.Controllers;

public class GrantRequest
{
    [Required, EmailAddress, MaxLength(256)]
    public string UserEmail { get; set; } = "";

    [Required]
    public string Level { get; set; } = "";
}

[ApiController]
[Route("api/documents/{id:guid}/permissions")]
[Authorize]
public class PermissionsController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly UserManager<AppUser> _users;
    private readonly IDocumentAuthorizationService _authz;
    private readonly IAuditService _audit;
    private readonly ILogger<PermissionsController> _logger;

    public PermissionsController(AppDbContext db, UserManager<AppUser> users,
        IDocumentAuthorizationService authz, IAuditService audit, ILogger<PermissionsController> logger)
    {
        _db = db;
        _users = users;
        _authz = authz;
        _audit = audit;
        _logger = logger;
    }

    // The acting user always comes from the session, never from the request body.
    private Guid CurrentUserId => Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);

    // Denials are always enforced. If recording one fails, access is still denied and the failure is logged.
    private async Task AuditDeniedAsync(string action, Guid documentId, string reason)
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

    // Someone who cannot see the document gets 404; someone who can see it but may not manage it gets 403.
    private IActionResult DenyResult(string? reason) =>
        reason is "owner_only" or "insufficient_level"
            ? StatusCode(StatusCodes.Status403Forbidden)
            : NotFound();

    [HttpPost]
    public async Task<IActionResult> Grant(Guid id, [FromBody] GrantRequest request, CancellationToken ct)
    {
        var auth = await _authz.AuthorizeAsync(CurrentUserId, id, DocumentAccess.ManagePermissions, ct);
        if (!auth.Allowed)
        {
            await AuditDeniedAsync("permission.grant", id, auth.DenyReason ?? "denied");
            return DenyResult(auth.DenyReason);
        }

        DocumentLevel level;
        if (request.Level.Equals("Read", StringComparison.OrdinalIgnoreCase)) level = DocumentLevel.Read;
        else if (request.Level.Equals("Edit", StringComparison.OrdinalIgnoreCase)) level = DocumentLevel.Edit;
        else return BadRequest(new ProblemDetails { Status = 400, Title = "Level must be Read or Edit." });

        var target = await _users.FindByEmailAsync(request.UserEmail);
        if (target is null || !target.IsActive || target.Id == CurrentUserId)
        {
            await AuditDeniedAsync("permission.grant", id, "invalid_target");
            return BadRequest(new ProblemDetails { Status = 400, Title = "Access cannot be granted to this user." });
        }

        try
        {
            await using var tx = await _db.Database.BeginTransactionAsync(ct);

            var existing = await _db.DocumentPermissions.FirstOrDefaultAsync(
                p => p.DocumentId == id && p.UserId == target.Id && p.RevokedUtc == null, ct);

            if (existing is null)
            {
                _db.DocumentPermissions.Add(new DocumentPermission
                {
                    Id = Guid.NewGuid(),
                    DocumentId = id,
                    UserId = target.Id,
                    Level = level,
                    GrantedByUserId = CurrentUserId,
                    GrantedUtc = DateTime.UtcNow
                });
            }
            else
            {
                existing.Level = level;
            }

            await _db.SaveChangesAsync(ct);
            await _audit.RecordAsync(CurrentUserId, $"permission.grant level={level} target={target.Id:N}",
                id, AuditOutcome.Success, null, ct);
            await tx.CommitAsync(ct);
        }
        catch (DbUpdateException)
        {
            // Two concurrent grants raced on the unique index; the caller can simply retry.
            return Conflict();
        }

        return Ok(new { documentId = id, userId = target.Id, level = level.ToString() });
    }

    [HttpDelete("{userId:guid}")]
    public async Task<IActionResult> Revoke(Guid id, Guid userId, CancellationToken ct)
    {
        var auth = await _authz.AuthorizeAsync(CurrentUserId, id, DocumentAccess.ManagePermissions, ct);
        if (!auth.Allowed)
        {
            await AuditDeniedAsync("permission.revoke", id, auth.DenyReason ?? "denied");
            return DenyResult(auth.DenyReason);
        }

        await using var tx = await _db.Database.BeginTransactionAsync(ct);

        var grant = await _db.DocumentPermissions.FirstOrDefaultAsync(
            p => p.DocumentId == id && p.UserId == userId && p.RevokedUtc == null, ct);
        if (grant is null) return NotFound();

        grant.RevokedUtc = DateTime.UtcNow;
        await _db.SaveChangesAsync(ct);
        await _audit.RecordAsync(CurrentUserId, $"permission.revoke target={userId:N}",
            id, AuditOutcome.Success, null, ct);
        await tx.CommitAsync(ct);

        return NoContent();
    }
}