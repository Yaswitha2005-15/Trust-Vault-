using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using TrustVault.Api.Data;

namespace TrustVault.Api.Audit;

public sealed record AuditVerification(bool Valid, int EventCount, long? FirstBrokenEventId, string HeadHash);

public interface IAuditService
{
    // Joins the caller's transaction if there is one, otherwise runs in its own.
    // Throws on failure, so callers decide whether to fail closed.
    Task RecordAsync(Guid? actorUserId, string action, Guid? documentId, string outcome,
        string? denyReason, CancellationToken ct = default);

    Task<AuditVerification> VerifyAsync(CancellationToken ct = default);
}

public sealed class AuditService : IAuditService
{
    private static readonly string Genesis = new('0', 64);
    private const long ChainLockKey = 727274;

    private readonly AppDbContext _db;
    public AuditService(AppDbContext db) => _db = db;

    public static string ComputeHash(string prevHash, AuditEvent e)
    {
        var canonical = string.Join("|",
            prevHash,
            e.OccurredUtc.Ticks,
            e.ActorUserId?.ToString("N") ?? "-",
            e.Action,
            e.DocumentId?.ToString("N") ?? "-",
            e.Outcome,
            e.DenyReason ?? "-");
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    public async Task RecordAsync(Guid? actorUserId, string action, Guid? documentId, string outcome,
        string? denyReason, CancellationToken ct = default)
    {
        var ownsTransaction = _db.Database.CurrentTransaction is null;
        await using var tx = ownsTransaction ? await _db.Database.BeginTransactionAsync(ct) : null;

        // Only one transaction at a time may extend the chain; the lock is released at commit/rollback.
        await _db.Database.ExecuteSqlRawAsync($"SELECT pg_advisory_xact_lock({ChainLockKey})", ct);

        var prevHash = await _db.AuditEvents.AsNoTracking()
            .OrderByDescending(e => e.Id)
            .Select(e => e.Hash)
            .FirstOrDefaultAsync(ct) ?? Genesis;

        // Postgres stores microseconds; truncate so the hash survives a database round trip.
        var now = DateTime.UtcNow;
        now = new DateTime(now.Ticks - now.Ticks % 10, DateTimeKind.Utc);

        var auditEvent = new AuditEvent
        {
            OccurredUtc = now,
            ActorUserId = actorUserId,
            Action = action,
            DocumentId = documentId,
            Outcome = outcome,
            DenyReason = denyReason,
            PrevHash = prevHash
        };
        auditEvent.Hash = ComputeHash(prevHash, auditEvent);

        _db.AuditEvents.Add(auditEvent);
        await _db.SaveChangesAsync(ct);

        if (ownsTransaction) await tx!.CommitAsync(ct);
    }

    public async Task<AuditVerification> VerifyAsync(CancellationToken ct = default)
    {
        var expectedPrev = Genesis;
        var count = 0;

        await foreach (var e in _db.AuditEvents.AsNoTracking().OrderBy(x => x.Id).AsAsyncEnumerable().WithCancellation(ct))
        {
            if (e.PrevHash != expectedPrev || ComputeHash(e.PrevHash, e) != e.Hash)
                return new AuditVerification(false, count, e.Id, expectedPrev);

            expectedPrev = e.Hash;
            count++;
        }

        return new AuditVerification(true, count, null, expectedPrev);
    }
}