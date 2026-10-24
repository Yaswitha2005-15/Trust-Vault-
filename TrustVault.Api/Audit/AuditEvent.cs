namespace TrustVault.Api.Audit;

public static class AuditOutcome
{
    public const string Success = "Success";
    public const string Denied = "Denied";
}

public class AuditEvent
{
    public long Id { get; set; }
    public DateTime OccurredUtc { get; set; }
    public Guid? ActorUserId { get; set; }
    public string Action { get; set; } = "";
    public Guid? DocumentId { get; set; }
    public string Outcome { get; set; } = "";
    public string? DenyReason { get; set; }
    public string PrevHash { get; set; } = "";
    public string Hash { get; set; } = "";
}