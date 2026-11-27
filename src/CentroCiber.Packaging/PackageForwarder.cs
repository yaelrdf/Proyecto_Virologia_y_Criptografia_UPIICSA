using CentroCiber.Crypto.Identity;
using CentroCiber.Crypto.Protocol;

namespace CentroCiber.Packaging;

/// <summary>Reenvío con re-firma (§9.6).</summary>
public static class PackageForwarder
{
    /// <summary>
    /// Conserva <c>datos.enc</c>, <c>publicParameters</c>, <c>keyRef</c>, <c>producerNode</c> y
    /// <c>algorithmCode</c>; genera nuevo <c>timestampUtc</c>; pone el propio <c>nodeId</c> en
    /// <c>sourceNode</c>, su certificado y vuelve a firmar. El <c>packetId</c> es nuevo, salvo en los
    /// algoritmos cuyo AAD es el <c>packetId</c> (AESGCM, CHACHA20): ahí se conserva para que el dueño
    /// pueda descifrar (ADR 0015).
    /// </summary>
    public static BuiltPackage Forward(ValidatedPackage original, NodeIdentity me, string sourceIp, TimeProvider clock)
    {
        var timestamp = Identifiers.TruncateToSeconds(clock.GetUtcNow());
        var m = original.Manifest;
        var unsigned = m with
        {
            PacketId = AlgorithmCatalog.PacketIdAadAlgorithms.Contains(m.AlgorithmCode) ? m.PacketId : Identifiers.NewUuid(),
            TimestampUtc = Identifiers.FormatTimestamp(timestamp),
            SourceNode = me.NodeId,
            SourceTeam = int.Parse(me.NodeId.AsSpan(2), System.Globalization.CultureInfo.InvariantCulture),
            SourceIp = sourceIp,
            CertificateThumbprintSha256 = me.Thumbprint,
            ManifestSignatureBase64 = string.Empty,
        };
        return PackageBuilder.Sign(unsigned, original.Data, me, timestamp);
    }
}
