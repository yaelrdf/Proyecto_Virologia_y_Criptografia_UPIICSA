using System.Text;
using CentroCiber.Crypto.Protocol;

namespace CentroCiber.Packaging;

/// <summary>Cadena de firma del manifiesto (§8.4).</summary>
public static class SignatureChain
{
    /// <summary>
    /// <c>version|packetType|packetId|sourceNode|producerNode|algorithmCode|operation|timestampUtc|encryptedSha256|publicParametersSha256|certificateThumbprintSha256</c>
    /// </summary>
    public static string Build(Manifest m) => string.Join(ProtocolConstants.SignatureChainSeparator,
        m.Version, m.PacketType, m.PacketId, m.SourceNode, m.ProducerNode, m.AlgorithmCode, m.Operation,
        m.TimestampUtc, m.EncryptedSha256, m.PublicParametersSha256, m.CertificateThumbprintSha256);

    public static byte[] Bytes(Manifest m) => Encoding.UTF8.GetBytes(Build(m));
}
