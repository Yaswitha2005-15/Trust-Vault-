using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TrustVault.Api.Audit;
using TrustVault.Api.Data;

namespace TrustVault.Api.Controllers;

public class CreateUserRequest
{
    [Required, EmailAddress, MaxLength(256)]
    public string Email { get; set; } = "";

    [Required, MaxLength(128)]
    public string Password { get; set; } = "";

    [Required]
    public string Role { get; set; } = "";
}

[ApiController]
[Route("api/admin/users")]
[Authorize(Roles = Roles.Administrator)]
public class AdminUsersController : ControllerBase
{
    private readonly UserManager<AppUser> _users;
    private readonly AppDbContext _db;
    private readonly IAuditService _audit;

    public AdminUsersController(UserManager<AppUser> users, AppDbContext db, IAuditService audit)
    {
        _users = users;
        _db = db;
        _audit = audit;
    }

    private Guid AdminId => Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);

    [HttpGet]
    public async Task<IActionResult> List(CancellationToken ct)
    {
        var users = await _users.Users.AsNoTracking().OrderBy(u => u.Email).Take(200).ToListAsync(ct);
        var result = new List<object>();
        foreach (var u in users)
        {
            var roles = await _users.GetRolesAsync(u);
            result.Add(new { u.Id, u.Email, u.IsActive, Roles = roles });
        }
        return Ok(result);
    }

    // Administrators are not created through the API, so nobody can escalate to admin this way.
    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateUserRequest request, CancellationToken ct)
    {
        if (request.Role != Roles.Owner && request.Role != Roles.Viewer)
            return BadRequest(new ProblemDetails { Status = 400, Title = "Role must be Owner or Viewer." });

        var email = request.Email.Trim();

        await using var tx = await _db.Database.BeginTransactionAsync(ct);

        var user = new AppUser { Id = Guid.NewGuid(), UserName = email, Email = email, EmailConfirmed = true };
        var created = await _users.CreateAsync(user, request.Password);
        if (!created.Succeeded)
            return BadRequest(new ProblemDetails
            {
                Status = 400,
                Title = "The user could not be created.",
                Detail = string.Join(" ", created.Errors.Select(e => e.Description))
            });

        await _users.AddToRoleAsync(user, request.Role);
        await _audit.RecordAsync(AdminId, $"user.create role={request.Role} target={user.Id:N}", null, AuditOutcome.Success, null, ct);
        await tx.CommitAsync(ct);

        return Ok(new { user.Id, user.Email, Role = request.Role });
    }

    // Two layers: the IsActive flag is checked on every request, and the security stamp is rotated.
    [HttpPost("{id:guid}/deactivate")]
    public async Task<IActionResult> Deactivate(Guid id, CancellationToken ct)
    {
        var user = await _users.FindByIdAsync(id.ToString());
        if (user is null) return NotFound();

        if (id == AdminId || await _users.IsInRoleAsync(user, Roles.Administrator))
            return BadRequest(new ProblemDetails { Status = 400, Title = "Administrator accounts cannot be deactivated here." });

        await using var tx = await _db.Database.BeginTransactionAsync(ct);

        user.IsActive = false;
        var updated = await _users.UpdateAsync(user);
        if (!updated.Succeeded)
            throw new InvalidOperationException(string.Join("; ", updated.Errors.Select(e => e.Description)));
        await _users.UpdateSecurityStampAsync(user);

        await _audit.RecordAsync(AdminId, $"user.deactivate target={id:N}", null, AuditOutcome.Success, null, ct);
        await tx.CommitAsync(ct);

        return NoContent();
    }

    [HttpPost("{id:guid}/activate")]
    public async Task<IActionResult> Activate(Guid id, CancellationToken ct)
    {
        var user = await _users.FindByIdAsync(id.ToString());
        if (user is null) return NotFound();

        await using var tx = await _db.Database.BeginTransactionAsync(ct);

        user.IsActive = true;
        var updated = await _users.UpdateAsync(user);
        if (!updated.Succeeded)
            throw new InvalidOperationException(string.Join("; ", updated.Errors.Select(e => e.Description)));

        await _audit.RecordAsync(AdminId, $"user.activate target={id:N}", null, AuditOutcome.Success, null, ct);
        await tx.CommitAsync(ct);

        return NoContent();
    }
}