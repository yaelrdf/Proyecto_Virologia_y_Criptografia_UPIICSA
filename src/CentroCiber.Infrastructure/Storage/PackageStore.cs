namespace CentroCiber.Infrastructure.Storage;

/// <summary>
/// Almacén de zips en disco. Los nombres se generan aquí (no se usa el nombre recibido),
/// para evitar rutas maliciosas.
/// </summary>
public sealed class PackageStore
{
    private readonly string root;

    public PackageStore(string root)
    {
        this.root = root;
        Directory.CreateDirectory(root);
    }

    public string Root => root;

    /// <summary>Guarda el zip y devuelve la ruta relativa.</summary>
    public async Task<string> SaveAsync(string folder, string packetId, ReadOnlyMemory<byte> zip, CancellationToken ct)
    {
        var safeFolder = Path.GetFileName(folder);
        var safeName = Path.GetFileName(packetId) + ".zip";
        var dir = Path.Combine(root, safeFolder);
        Directory.CreateDirectory(dir);
        var relative = Path.Combine(safeFolder, safeName);
        await File.WriteAllBytesAsync(Path.Combine(root, relative), zip.ToArray(), ct);
        return relative;
    }

    public async Task<byte[]> ReadAsync(string relativePath, CancellationToken ct) =>
        await File.ReadAllBytesAsync(Resolve(relativePath), ct);

    public void Delete(string relativePath)
    {
        var full = Resolve(relativePath);
        if (File.Exists(full))
        {
            File.Delete(full);
        }
    }

    private string Resolve(string relativePath)
    {
        var full = Path.GetFullPath(Path.Combine(root, relativePath));
        var rootFull = Path.GetFullPath(root) + Path.DirectorySeparatorChar;
        if (!full.StartsWith(rootFull, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Ruta fuera del almacén de paquetes.");
        }

        return full;
    }
}
