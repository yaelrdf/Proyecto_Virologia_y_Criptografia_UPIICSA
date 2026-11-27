using System.Net.Http.Headers;
using System.Text.Json;
using CentroCiber.Application;
using CentroCiber.Crypto.Identity;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Packaging;
using CentroCiber.Packaging.Client;
using Microsoft.Extensions.DependencyInjection;

namespace CentroCiber.Api.Tests;

/// <summary>Identidades de prueba compartidas (RSA-2048 es costoso).</summary>
public static class Ids
{
    public static NodeIdentity Eq03 { get; } = NodeIdentity.Create(3, TimeProvider.System);

    public static NodeIdentity Eq05 { get; } = NodeIdentity.Create(5, TimeProvider.System);
}

public static class ApiHelpers
{
    public static readonly string HmacKey = Convert.ToBase64String(Enumerable.Range(0, 32).Select(i => (byte)i).ToArray());

    public static NodeContext Node(this NodeFactory f) => f.Services.GetRequiredService<NodeContext>();

    public static async Task<HttpResponseMessage> PostCryptoAsync(this HttpClient client, string operation, SignedCryptoRequest req,
        byte[]? payload = null, byte[]? package = null, string? nodeHeader = null)
    {
        using var message = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/crypto/" + operation, UriKind.Relative))
        {
            Content = req.ToMultipart(payload, "documento.txt", null, package),
        };
        CryptoRequestBuilder.AddProtocolHeaders(message, nodeHeader ?? req.Request.RequesterNode, req.Request.RequestId);
        return await client.SendAsync(message);
    }

    public static SignedCryptoRequest Request(NodeFactory f, NodeIdentity requester, string algorithm, string operation,
        Dictionary<string, string>? secrets = null, Dictionary<string, string>? options = null, Func<CryptoRequestSpec, CryptoRequestSpec>? edit = null)
    {
        var spec = new CryptoRequestSpec
        {
            TargetNode = "EQ08",
            TargetCertificate = f.Node().Identity.Certificate,
            AlgorithmCode = algorithm,
            Operation = operation,
            OriginalFileName = "documento.txt",
            Secrets = secrets,
            Options = options,
        };
        return CryptoRequestBuilder.Create(requester, edit?.Invoke(spec) ?? spec, TimeProvider.System);
    }

    public static async Task<string> ProblemCodeAsync(this HttpResponseMessage response)
    {
        response.Content.Headers.ContentType?.MediaType.ShouldBe(ProtocolConstants.ProblemContentType);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        doc.RootElement.GetProperty("nodeId").GetString().ShouldBe("EQ08");
        doc.RootElement.GetProperty("type").GetString()!.ShouldStartWith(ProtocolConstants.ErrorTypeBase);
        doc.RootElement.GetProperty("status").GetInt32().ShouldBe((int)response.StatusCode);
        doc.RootElement.GetProperty("detail").GetString().ShouldNotBeNullOrWhiteSpace();
        return doc.RootElement.GetProperty("code").GetString()!;
    }

    public static async Task<HttpResponseMessage> PostPackageAsync(this HttpClient client, byte[] zip)
    {
        var content = new MultipartFormDataContent();
        var file = new ByteArrayContent(zip);
        file.Headers.ContentType = new MediaTypeHeaderValue("application/zip");
        content.Add(file, "package", "paquete.zip");
        return await client.PostAsync(new Uri("/api/requests/receive", UriKind.Relative), content);
    }

    /// <summary>Paquete HASHSHA firmado por <paramref name="signer"/>.</summary>
    public static BuiltPackage HashPackage(NodeIdentity signer, string text = "hola EQ08")
    {
        var data = System.Text.Encoding.UTF8.GetBytes(text);
        var output = new Crypto.Algorithms.HashShaAlgorithm().Forward(new(data, new Dictionary<string, string>(), new Dictionary<string, string>()));
        return PackageBuilder.Build(new PackageContent
        {
            PacketType = "package",
            AlgorithmCode = "HASHSHA",
            AlgorithmName = output.AlgorithmName,
            Operation = "forward",
            PayloadMode = "text",
            OriginalFileName = "mensaje.txt",
            OriginalSizeBytes = data.Length,
            Data = output.Data,
            PublicParameters = output.PublicParameters,
        }, signer, "127.0.0.1:5003", TimeProvider.System);
    }
}
