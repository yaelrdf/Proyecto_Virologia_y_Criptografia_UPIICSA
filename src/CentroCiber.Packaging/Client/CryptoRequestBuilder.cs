using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using CentroCiber.Crypto.Envelope;
using CentroCiber.Crypto.Identity;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Crypto.Signing;
using CentroCiber.Packaging.Contracts;

namespace CentroCiber.Packaging.Client;

/// <summary>Petición <c>/api/crypto/*</c> firmada, lista para enviarse (§10.6).</summary>
public sealed record SignedCryptoRequest(CryptoRequest Request, byte[] RequestBytes, string SignatureBase64, string RequesterCertificatePem)
{
    /// <summary>Arma el <c>multipart/form-data</c> con las partes de la tabla de §10.6.</summary>
    public MultipartFormDataContent ToMultipart(byte[]? payload = null, string? payloadFileName = null, byte[]? cover = null, byte[]? packageZip = null)
    {
        var content = new MultipartFormDataContent();
        var request = new ByteArrayContent(RequestBytes);
        request.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        content.Add(request, ProtocolConstants.PartRequest, "request.json");
        content.Add(new StringContent(SignatureBase64, Encoding.ASCII, "text/plain"), ProtocolConstants.PartRequestSignature);
        var cert = new StringContent(RequesterCertificatePem, Encoding.ASCII);
        cert.Headers.ContentType = new MediaTypeHeaderValue(ProtocolConstants.PemContentType);
        content.Add(cert, ProtocolConstants.PartRequesterCertificate, "certificado.pem");
        if (payload is not null)
        {
            content.Add(Binary(payload, "application/octet-stream"), ProtocolConstants.PartPayload, payloadFileName ?? "payload.bin");
        }

        if (cover is not null)
        {
            content.Add(Binary(cover, "application/octet-stream"), ProtocolConstants.PartCover, "cover.bin");
        }

        if (packageZip is not null)
        {
            content.Add(Binary(packageZip, ProtocolConstants.ZipContentType), ProtocolConstants.PartPackage, "package.zip");
        }

        return content;
    }

    private static ByteArrayContent Binary(byte[] data, string mediaType)
    {
        var c = new ByteArrayContent(data);
        c.Headers.ContentType = new MediaTypeHeaderValue(mediaType);
        return c;
    }
}

/// <summary>Parámetros de una petición saliente.</summary>
public sealed record CryptoRequestSpec
{
    public required string TargetNode { get; init; }

    /// <summary>Certificado del dueño, para cifrar los secretos (§8.3).</summary>
    public X509Certificate2? TargetCertificate { get; init; }

    public required string AlgorithmCode { get; init; }

    public required string Operation { get; init; }

    public string PayloadMode { get; init; } = ProtocolConstants.PayloadFile;

    public string OriginalFileName { get; init; } = ProtocolConstants.DefaultTextFileName;

    public IReadOnlyDictionary<string, string>? Options { get; init; }

    public IReadOnlyDictionary<string, string>? Secrets { get; init; }

    public string? KeyId { get; init; }

    public string? RequestId { get; init; }

    public string? Version { get; init; }
}

/// <summary>Construye y firma peticiones <c>/api/crypto/*</c>.</summary>
public static class CryptoRequestBuilder
{
    public static SignedCryptoRequest Create(NodeIdentity requester, CryptoRequestSpec spec, TimeProvider clock)
    {
        var requestId = spec.RequestId ?? Identifiers.NewUuid();
        CcEnvelope? secrets = null;
        if (spec.Secrets is { Count: > 0 })
        {
            var cert = spec.TargetCertificate
                ?? throw new InvalidOperationException("Se necesita el certificado del dueño para cifrar los secretos.");
            secrets = EnvelopeCrypto.SealSecrets(spec.Secrets, cert, spec.TargetNode, requestId);
        }

        var request = new CryptoRequest
        {
            Version = spec.Version ?? ProtocolConstants.ProtocolVersion,
            RequestId = requestId,
            RequesterNode = requester.NodeId,
            TargetNode = spec.TargetNode,
            TimestampUtc = Identifiers.FormatTimestamp(clock.GetUtcNow()),
            AlgorithmCode = spec.AlgorithmCode,
            Operation = spec.Operation,
            PayloadMode = spec.PayloadMode,
            OriginalFileName = spec.OriginalFileName,
            Options = spec.Options ?? new Dictionary<string, string>(),
            KeyId = spec.KeyId,
            Secrets = secrets,
        };
        return Sign(requester, request);
    }

    /// <summary>Firma los bytes exactos del JSON de la petición (§10.6 <c>requestSignature</c>).</summary>
    public static SignedCryptoRequest Sign(NodeIdentity requester, CryptoRequest request)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(request, ProtocolJson.Compact);
        return new SignedCryptoRequest(request, bytes, RsaPss.SignBase64(requester.PrivateKey, bytes), requester.CertificatePem);
    }

    /// <summary>Agrega los encabezados <c>X-CC-*</c> (§10.1).</summary>
    public static void AddProtocolHeaders(HttpRequestMessage message, string nodeId, string requestId)
    {
        message.Headers.Add(ProtocolConstants.HeaderNode, nodeId);
        message.Headers.Add(ProtocolConstants.HeaderProtocol, ProtocolConstants.ProtocolVersion);
        message.Headers.Add(ProtocolConstants.HeaderRequestId, requestId);
    }
}
