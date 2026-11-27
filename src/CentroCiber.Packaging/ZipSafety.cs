using System.IO.Compression;
using CentroCiber.Crypto.Protocol;

namespace CentroCiber.Packaging;

/// <summary>Lectura segura de zips en memoria (§9.3, §13.1 #2–#4).</summary>
public static class ZipSafety
{
    /// <summary>Nombre plano: sin carpetas, sin rutas, sin <c>..</c> y sin archivos ocultos.</summary>
    public static bool IsFlatName(string fullName) =>
        !string.IsNullOrEmpty(fullName)
        && !fullName.Contains('/', StringComparison.Ordinal)
        && !fullName.Contains('\\', StringComparison.Ordinal)
        && !fullName.Contains("..", StringComparison.Ordinal)
        && !fullName.StartsWith('.')
        && !fullName.Contains(':', StringComparison.Ordinal);

    public static ZipArchive Open(byte[] zip)
    {
        try
        {
            var archive = new ZipArchive(new MemoryStream(zip, writable: false), ZipArchiveMode.Read, leaveOpen: false);
            _ = archive.Entries.Count;
            return archive;
        }
        catch (InvalidDataException ex)
        {
            throw new ProtocolException(ErrorCodes.ZipInvalid, "El archivo no es un zip válido.", ex);
        }
    }

    /// <summary>§13.1 #4: tamaño descomprimido y razón de compresión.</summary>
    public static void CheckBomb(IReadOnlyCollection<ZipArchiveEntry> entries, long maxUncompressed)
    {
        long total = 0;
        long compressed = 0;
        foreach (var e in entries)
        {
            total += e.Length;
            compressed += e.CompressedLength;
        }

        if (total > maxUncompressed)
        {
            throw new ProtocolException(ErrorCodes.ZipBomb, "El contenido descomprimido supera 200 MB.");
        }

        if (total > 0 && (compressed == 0 || total / (double)compressed > ProtocolConstants.MaxCompressionRatio))
        {
            throw new ProtocolException(ErrorCodes.ZipBomb, "La razón de compresión supera 100:1.");
        }
    }

    /// <summary>Lee una entrada sin exceder su tamaño declarado (defensa contra encabezados falsos).</summary>
    public static byte[] ReadAll(ZipArchiveEntry entry)
    {
        try
        {
            using var stream = entry.Open();
            var buffer = new byte[entry.Length];
            var read = 0;
            while (read < buffer.Length)
            {
                var n = stream.Read(buffer, read, buffer.Length - read);
                if (n == 0)
                {
                    break;
                }

                read += n;
            }

            if (read != buffer.Length || stream.ReadByte() != -1)
            {
                throw new ProtocolException(ErrorCodes.ZipBomb, $"El tamaño real de {entry.Name} no coincide con el declarado.");
            }

            return buffer;
        }
        catch (InvalidDataException ex)
        {
            throw new ProtocolException(ErrorCodes.ZipInvalid, $"No se pudo leer {entry.Name}.", ex);
        }
    }

    /// <summary>Crea un zip con entradas planas. Los datos binarios van sin comprimir (<c>store</c>).</summary>
    public static byte[] Write(IEnumerable<(string Name, byte[] Data, bool Compress)> entries, DateTimeOffset timestamp)
    {
        using var ms = new MemoryStream();
        using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, data, compress) in entries)
            {
                var entry = archive.CreateEntry(name, compress ? CompressionLevel.Optimal : CompressionLevel.NoCompression);
                entry.LastWriteTime = timestamp;
                using var s = entry.Open();
                s.Write(data);
            }
        }

        return ms.ToArray();
    }
}
