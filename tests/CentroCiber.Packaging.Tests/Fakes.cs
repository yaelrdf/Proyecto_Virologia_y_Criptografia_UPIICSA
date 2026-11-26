using System.Collections.Concurrent;
using System.IO.Compression;
using System.Text.Json;
using System.Text.Json.Nodes;
using CentroCiber.Crypto.Identity;

namespace CentroCiber.Packaging.Tests;

public sealed class MemoryReplayGuard : IReplayGuard
{
    private readonly ConcurrentDictionary<string, bool> seen = new();

    public Task<bool> HasSeenAsync(string kind, string id, CancellationToken ct) => Task.FromResult(seen.ContainsKey(kind + ":" + id));

    public Task<bool> TryMarkSeenAsync(string kind, string id, CancellationToken ct) => Task.FromResult(seen.TryAdd(kind + ":" + id, true));
}

public sealed class MemoryTrust : ITrustLookup
{
    public Dictionary<string, string> Pinned { get; } = [];

    public Task<string?> GetPinnedThumbprintAsync(string nodeId, CancellationToken ct) =>
        Task.FromResult(Pinned.TryGetValue(nodeId, out var t) ? t : null);
}

/// <summary>Herramientas para fabricar zips alterados.</summary>
public static class ZipTools
{
    public static Dictionary<string, byte[]> Read(byte[] zip)
    {
        using var a = new ZipArchive(new MemoryStream(zip), ZipArchiveMode.Read);
        return a.Entries.ToDictionary(e => e.FullName, e =>
        {
            using var s = e.Open();
            using var ms = new MemoryStream();
            s.CopyTo(ms);
            return ms.ToArray();
        });
    }

    public static byte[] Write(IEnumerable<KeyValuePair<string, byte[]>> entries, CompressionLevel level = CompressionLevel.NoCompression)
    {
        using var ms = new MemoryStream();
        using (var a = new ZipArchive(ms, ZipArchiveMode.Create, true))
        {
            foreach (var (name, data) in entries)
            {
                var e = a.CreateEntry(name, level);
                using var s = e.Open();
                s.Write(data);
            }
        }

        return ms.ToArray();
    }

    /// <summary>Modifica el manifiesto (como JSON) y opcionalmente vuelve a firmar con <paramref name="signer"/>.</summary>
    public static byte[] EditManifest(byte[] zip, Action<JsonObject> edit, NodeIdentity? signer = null)
    {
        var entries = Read(zip);
        var node = JsonNode.Parse(entries["manifest.json"])!.AsObject();
        edit(node);
        if (signer is not null)
        {
            var m = node.Deserialize<Manifest>(ProtocolJson.Options)!;
            node["manifestSignatureBase64"] = Crypto.Signing.RsaPss.SignBase64(signer.PrivateKey, SignatureChain.Bytes(m));
        }

        entries["manifest.json"] = JsonSerializer.SerializeToUtf8Bytes(node);
        return Write(entries);
    }
}
