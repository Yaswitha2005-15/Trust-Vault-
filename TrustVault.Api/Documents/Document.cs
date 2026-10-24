namespace TrustVault.Api.Documents;

public enum DocumentLevel
{
    Read = 1,
    Edit = 2
}

public class Document
{
    public Guid Id { get; set; }
    public Guid OwnerId { get; set; }
    public string Title { get; set; } = "";
    public string? Category { get; set; }
    public string OriginalFileName { get; set; } = "";
    public Guid StoredFileId { get; set; }
    public string ContentType { get; set; } = "";
    public long SizeBytes { get; set; }
    public string Sha256 { get; set; } = "";
    public DateTime CreatedUtc { get; set; }
    public DateTime UpdatedUtc { get; set; }
    public DateTime? DeletedUtc { get; set; }
}

public class DocumentPermission
{
    public Guid Id { get; set; }
    public Guid DocumentId { get; set; }
    public Guid UserId { get; set; }
    public DocumentLevel Level { get; set; }
    public Guid GrantedByUserId { get; set; }
    public DateTime GrantedUtc { get; set; }
    public DateTime? RevokedUtc { get; set; }
}