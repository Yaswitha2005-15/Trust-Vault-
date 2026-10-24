using System.Text;

namespace TrustVault.Api.Documents;

public static class UploadValidator
{
    public const long MaxBytes = 10 * 1024 * 1024;

    // Allowlist: extension -> content type chosen by the SERVER (the client's header is never trusted).
    private static readonly Dictionary<string, string> ContentTypes = new()
    {
        [".pdf"] = "application/pdf",
        [".png"] = "image/png",
        [".jpg"] = "image/jpeg",
        [".jpeg"] = "image/jpeg",
        [".txt"] = "text/plain"
    };

    private static readonly byte[] Pdf = Encoding.ASCII.GetBytes("%PDF-");
    private static readonly byte[] Png = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
    private static readonly byte[] Jpeg = { 0xFF, 0xD8, 0xFF };

    public static bool TryValidate(string fileName, long length, byte[] header, int headerLength,
        out string contentType, out string error)
    {
        contentType = "";
        error = "";

        if (length <= 0) { error = "The file is empty."; return false; }
        if (length > MaxBytes) { error = "The file is too large (limit 10 MB)."; return false; }

        var extension = Path.GetExtension(fileName).ToLowerInvariant();
        if (!ContentTypes.TryGetValue(extension, out var type)) { error = "This file type is not allowed."; return false; }

        var signatureOk = extension switch
        {
            ".pdf" => StartsWith(header, headerLength, Pdf),
            ".png" => StartsWith(header, headerLength, Png),
            ".jpg" or ".jpeg" => StartsWith(header, headerLength, Jpeg),
            ".txt" => Array.IndexOf(header, (byte)0, 0, headerLength) < 0, // plain text has no NUL bytes
            _ => false
        };
        if (!signatureOk) { error = "The file content does not match its extension."; return false; }

        contentType = type;
        return true;
    }

    // The stored name is only metadata (never used as a path), but strip control characters
    // and quotes so it cannot cause trouble in logs or headers.
    public static string SanitizeFileName(string name)
    {
        var leaf = Path.GetFileName(name);
        var cleaned = new string(leaf.Where(c => !char.IsControl(c) && c != '"').ToArray()).Trim();
        if (cleaned.Length == 0) cleaned = "document";
        return cleaned.Length > 200 ? cleaned[^200..] : cleaned;
    }

    private static bool StartsWith(byte[] header, int length, byte[] signature)
    {
        if (length < signature.Length) return false;
        for (var i = 0; i < signature.Length; i++)
            if (header[i] != signature[i]) return false;
        return true;
    }
}