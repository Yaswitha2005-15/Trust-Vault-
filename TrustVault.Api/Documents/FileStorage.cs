using System.Security.Cryptography;

namespace TrustVault.Api.Documents;

public sealed record StoredFile(Guid Id, long SizeBytes, string Sha256);

public interface IFileStorage
{
    Task<StoredFile> SaveAsync(Stream content, CancellationToken ct = default);

    // Only an AuthorizedDocument can be opened: no authorisation, no bytes.
    Stream OpenRead(AuthorizedDocument authorized);

    void Delete(Guid storedFileId);
}

public sealed class LocalFileStorage : IFileStorage
{
    private readonly string _root;

    public LocalFileStorage(string root)
    {
        _root = Path.GetFullPath(root);
        Directory.CreateDirectory(_root);
    }

    // The path is built only from a Guid, so user input can never influence it.
    private string PathFor(Guid id) => Path.Combine(_root, id.ToString("N") + ".bin");

    public async Task<StoredFile> SaveAsync(Stream content, CancellationToken ct = default)
    {
        var id = Guid.NewGuid();
        var path = PathFor(id);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        long size = 0;

        try
        {
            await using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            var buffer = new byte[81920];
            int read;
            while ((read = await content.ReadAsync(buffer, ct)) > 0)
            {
                hash.AppendData(buffer, 0, read);
                await output.WriteAsync(buffer.AsMemory(0, read), ct);
                size += read;
            }
        }
        catch
        {
            if (File.Exists(path)) File.Delete(path);
            throw;
        }

        return new StoredFile(id, size, Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant());
    }

    public Stream OpenRead(AuthorizedDocument authorized) =>
        new FileStream(PathFor(authorized.Document.StoredFileId), FileMode.Open, FileAccess.Read, FileShare.Read);

    public void Delete(Guid storedFileId)
    {
        var path = PathFor(storedFileId);
        if (File.Exists(path)) File.Delete(path);
    }
}