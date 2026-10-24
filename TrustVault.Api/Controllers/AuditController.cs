using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TrustVault.Api.Audit;
using TrustVault.Api.Data;

namespace TrustVault.Api.Controllers;

[ApiController]
[Route("api/audit")]
[Authorize(Roles = Roles.Administrator + "," + Roles.Owner)]
public class AuditController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly IAuditService _audit;

    public AuditController(AppDbContext db, IAuditService audit)
    {
        _db = db;
        _audit = audit;
    }

    // Admins see everything; owners see only events about documents they own.
    [HttpGet]
    public async Task<IActionResult> List(CancellationToken ct)
    {
        var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);

        var query = _db.AuditEvents.AsNoTracking().AsQueryable();
        if (!User.IsInRole(Roles.Administrator))
        {
            query = query.Where(e => e.DocumentId != null &&
                _db.Documents.Any(d => d.Id == e.DocumentId && d.OwnerId == userId));
        }

        var events = await query
            .OrderByDescending(e => e.Id)
            .Take(500)
            .Select(e => new { e.Id, e.OccurredUtc, e.ActorUserId, e.Action, e.DocumentId, e.Outcome, e.DenyReason })
            .ToListAsync(ct);

        return Ok(events);
    }

    // Method-level Authorize is combined with the class-level one, so this is admin-only.
    [HttpGet("verify")]
    [Authorize(Roles = Roles.Administrator)]
    public async Task<IActionResult> Verify(CancellationToken ct) => Ok(await _audit.VerifyAsync(ct));
}