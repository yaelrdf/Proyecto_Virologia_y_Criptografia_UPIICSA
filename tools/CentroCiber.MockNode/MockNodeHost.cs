using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CentroCiber.Crypto.Envelope;
using CentroCiber.Crypto.Identity;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Crypto.Signing;
using CentroCiber.Packaging;
using CentroCiber.Packaging.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace CentroCiber.MockNode;

/// <summary>Opciones del nodo simulado.</summary>
public sealed record MockNodeOptions
{
    /// <summary>Equipo simulado (por defecto 1 = EQ01, dueño de AESGCM).</summary>
    public int TeamNumber { get; init; } = 1;

    /// <summary>0 = puerto libre aleatorio.</summary>
    public int Port { get; init; }

    public string BindAddress { get; init; } = "127.0.0.1";

    /// <summary>Responder siempre 202 + jobId (para probar la consulta de trabajos).</summary>
    public bool AlwaysAsync { get; init; }
}

/// <summary>
/// Nodo simulado que imita a otro equipo según el estándar v2.0: implementa <c>AESGCM</c> (#1)
/// con <c>status</c>, <c>certificate</c>, <c>algorithms</c>, <c>crypto/forward</c>, <c>crypto/inverse</c>
/// y <c>jobs</c>. Sirve para probar la delegación de EQ08 sin otros equipos.
/// </summary>
public sealed class MockNodeHost : IAsyncDisposable
{
    private readonly ConcurrentDictionary<string, (string Requester, byte[] Zip, string Name)> jobs = new();
    private readonly ConcurrentDictionary<string, bool> seen = new();
    private readonly MockNodeOptions options;
    private WebApplication? app;

    private MockNodeHost(MockNodeOptions options)
    {
        this.options = options;
        Identity = NodeIdentity.Create(options.TeamNumber, TimeProvider.System);
    }

    public NodeIdentity Identity { get; }

    public string NodeId => Identity.NodeId;

    public int Port { get; private set; }

    public int ForwardCalls { get; private set; }

    public int InverseCalls { get; private set; }

    public static async Task<MockNodeHost> StartAsync(MockNodeOptions? options = null)
    {
        var host = new MockNodeHost(options ?? new MockNodeOptions());
        await host.StartCoreAsync();
        return host;
    }

    private async Task StartCoreAsync()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        builder.Services.Configure<FormOptions>(f => f.MultipartBodyLengthLimit = ProtocolConstants.MaxBodyBytes + (1024 * 1024));
        builder.WebHost.ConfigureKestrel(k => k.Limits.MaxRequestBodySize = ProtocolConstants.MaxBodyBytes + (1024 * 1024));
        builder.WebHost.UseUrls($"http://{options.BindAddress}:{options.Port}");
        app = builder.Build();
        Map(app);
        await app.StartAsync();
        Port = new Uri(app.Urls.First()).Port;
    }

    private void Map(WebApplication web)
    {
        web.MapGet("/api/status", () => Results.Json(new StatusResponse
        {
            NodeId = NodeId,
            TeamNumber = options.TeamNumber,
            ProtocolVersion = ProtocolConstants.ProtocolVersion,
            Status = ProtocolConstants.StatusOnline,
            AcceptingPackages = true,
            HttpPort = Port,
            HttpsPort = null,
            Algorithms = [new StatusAlgorithm(1, AlgorithmCatalog.AesGcm)],
            CertificateThumbprintSha256 = Identity.Thumbprint,
            ServerTimeUtc = Identifiers.FormatTimestamp(DateTimeOffset.UtcNow),
        }));
        web.MapGet("/api/certificate", () => Results.Text(Identity.CertificatePem, ProtocolConstants.PemContentType));
        web.MapGet("/api/algorithms", () => Results.Json(new AlgorithmsResponse(NodeId,
        [
            new AlgorithmProfile
            {
                AlgorithmId = 1,
                AlgorithmCode = AlgorithmCatalog.AesGcm,
                Variants = ["AES-256-GCM", "AES-128-GCM"],
                Operations = new Dictionary<string, ProfileOperation>
                {
                    ["forward"] = new("cifrar", ["payload"]),
                    ["inverse"] = new("descifrar", ["package"]),
                },
                SecretParameters = [new ProfileSecret { Name = "key", Type = "base64", MinBytes = 16, RequiredFor = ["forward", "inverse"] }],
                Options = [new ProfileOption { Name = "keySizeBits", Type = "enum", Values = ["256", "128"], Default = "256" }],
                PublicParameters = ["keySizeBits", "nonceBase64", "tagBase64"],
                PayloadModes = ["text", "file", "image"],
                MaxPayloadBytes = ProtocolConstants.MaxBodyBytes,
            },
        ])));
        web.MapPost("/api/crypto/{operation}", HandleCryptoAsync);
        web.MapGet("/api/jobs/{jobId}", (string jobId) => jobs.ContainsKey(jobId)
            ? Results.Json(new JobStatusResponse { JobId = jobId, State = ProtocolConstants.JobDone, ProgressPercent = 100, ResultUrl = $"/api/jobs/{jobId}/result" })
            : Problem(ErrorCodes.JobNotFound, "jobId desconocido."));
        web.MapGet("/api/jobs/{jobId}/result", (string jobId, HttpRequest req) =>
            jobs.TryGetValue(jobId, out var job) && req.Headers[ProtocolConstants.HeaderNode] == job.Requester
                ? Results.File(job.Zip, ProtocolConstants.ZipContentType, job.Name)
                : Problem(ErrorCodes.JobNotFound, "jobId desconocido."));
    }

    private async Task<IResult> HandleCryptoAsync(string operation, HttpRequest http)
    {
        try
        {
            var form = await http.ReadFormAsync();
            var requestBytes = await Part(form, ProtocolConstants.PartRequest);
            var signature = Encoding.ASCII.GetString(await Part(form, ProtocolConstants.PartRequestSignature)).Trim();
            var certPem = Encoding.ASCII.GetString(await Part(form, ProtocolConstants.PartRequesterCertificate));
            var request = JsonSerializer.Deserialize<CryptoRequest>(requestBytes, ProtocolJson.Options)
                ?? throw new ProtocolException(ErrorCodes.Request, "request vacío.");
            using var requesterCert = CertificateTools.LoadAndValidate(certPem, request.RequesterNode, DateTimeOffset.UtcNow);
            if (!RsaPss.Verify(requesterCert, requestBytes, signature))
            {
                throw new ProtocolException(ErrorCodes.RequestSignature, "Firma de la petición inválida.");
            }

            if (request.TargetNode != NodeId || request.Operation != operation)
            {
                throw new ProtocolException(ErrorCodes.Request, "targetNode u operation incorrectos.");
            }

            PackageValidator.CheckTimestamp(request.TimestampUtc, TimeProvider.System);
            if (!seen.TryAdd(request.RequestId, true))
            {
                throw new ProtocolException(ErrorCodes.Duplicate, "requestId repetido.");
            }

            if (request.AlgorithmCode != AlgorithmCatalog.AesGcm)
            {
                throw new ProtocolException(ErrorCodes.AlgorithmNotProvided, $"{NodeId} no provee {request.AlgorithmCode}.");
            }

            var secrets = request.Secrets is null
                ? throw new ProtocolException(ErrorCodes.Params, "Falta el secreto key.")
                : EnvelopeCrypto.OpenSecrets(request.Secrets, Identity, request.RequestId);
            var key = Convert.FromBase64String(secrets.GetValueOrDefault("key") ?? throw new ProtocolException(ErrorCodes.Params, "Falta key."));
            if (key.Length is not (16 or 32))
            {
                throw new ProtocolException(ErrorCodes.Params, "key debe medir 16 o 32 bytes.");
            }

            BuiltPackage built;
            if (operation == ProtocolConstants.OperationForward)
            {
                ForwardCalls++;
                var payload = await Part(form, ProtocolConstants.PartPayload);
                built = Encrypt(request, payload, key);
            }
            else
            {
                InverseCalls++;
                var zip = await Part(form, ProtocolConstants.PartPackage);
                built = await DecryptAsync(request, zip, key, requesterCert);
            }

            CryptographicOperations.ZeroMemory(key);
            if (options.AlwaysAsync)
            {
                var jobId = Identifiers.NewUuid();
                jobs[jobId] = (request.RequesterNode, built.Zip, built.FileName);
                return Results.Json(new JobAccepted(jobId, $"/api/jobs/{jobId}", 1), statusCode: StatusCodes.Status202Accepted);
            }

            return Results.File(built.Zip, ProtocolConstants.ZipContentType, built.FileName);
        }
        catch (ProtocolException ex)
        {
            return Problem(ex.Code, ex.Message);
        }
        catch (Exception ex) when (ex is FormatException or JsonException or InvalidDataException)
        {
            return Problem(ErrorCodes.Request, ex.Message);
        }
    }

    private BuiltPackage Encrypt(CryptoRequest request, byte[] payload, byte[] key)
    {
        var packetId = Identifiers.NewUuid();
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var ciphertext = new byte[payload.Length];
        using (var aes = new AesGcm(key, 16))
        {
            aes.Encrypt(nonce, payload, ciphertext, tag, Encoding.UTF8.GetBytes(packetId)); // §4.2: AAD = packetId
        }

        var bits = (key.Length * 8).ToString(System.Globalization.CultureInfo.InvariantCulture);
        return PackageBuilder.Build(new PackageContent
        {
            PacketType = ProtocolConstants.PacketTypePackage,
            PacketId = packetId,
            RequestId = request.RequestId,
            AlgorithmCode = AlgorithmCatalog.AesGcm,
            AlgorithmName = $"AES-{bits}-GCM",
            Operation = ProtocolConstants.OperationForward,
            PayloadMode = request.PayloadMode,
            OriginalFileName = request.OriginalFileName,
            OriginalSizeBytes = payload.Length,
            Data = ciphertext,
            PublicParameters = new Dictionary<string, string>
            {
                ["keySizeBits"] = bits,
                ["nonceBase64"] = Convert.ToBase64String(nonce),
                ["tagBase64"] = Convert.ToBase64String(tag),
            },
        }, Identity, $"{options.BindAddress}:{Port}", TimeProvider.System);
    }

    private async Task<BuiltPackage> DecryptAsync(CryptoRequest request, byte[] zip, byte[] key, System.Security.Cryptography.X509Certificates.X509Certificate2 requesterCert)
    {
        var validator = new PackageValidator(TimeProvider.System, new MemoryReplay(), new NoTrust());
        var package = await validator.ValidateAsync(zip, PackageValidationOptions.ForInverse, CancellationToken.None);
        var m = package.Manifest;
        if (m.AlgorithmCode != AlgorithmCatalog.AesGcm)
        {
            throw new ProtocolException(ErrorCodes.Request, "El paquete no es AESGCM.");
        }

        var plaintext = new byte[package.Data.Length];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(Convert.FromBase64String(m.PublicParameters["nonceBase64"]), package.Data,
                Convert.FromBase64String(m.PublicParameters["tagBase64"]), plaintext, Encoding.UTF8.GetBytes(m.PacketId));
        }
        catch (Exception ex) when (ex is CryptographicException or KeyNotFoundException or FormatException)
        {
            throw new ProtocolException(ErrorCodes.Params, "No se pudo descifrar: clave o parámetros incorrectos.", ex);
        }

        var packetId = Identifiers.NewUuid();
        var sealedResult = EnvelopeCrypto.Seal(plaintext, requesterCert, request.RequesterNode, packetId, includeCiphertext: false);
        return PackageBuilder.Build(new PackageContent
        {
            PacketType = ProtocolConstants.PacketTypeResult,
            PacketId = packetId,
            RequestId = request.RequestId,
            AlgorithmCode = AlgorithmCatalog.AesGcm,
            AlgorithmName = m.AlgorithmName,
            Operation = ProtocolConstants.OperationInverse,
            PayloadMode = m.PayloadMode,
            OriginalFileName = m.OriginalFileName,
            OriginalSizeBytes = plaintext.Length,
            ContentType = m.ContentType,
            Data = sealedResult.Ciphertext,
            ResultEnvelope = sealedResult.Envelope,
        }, Identity, $"{options.BindAddress}:{Port}", TimeProvider.System);
    }

    private static async Task<byte[]> Part(IFormCollection form, string name)
    {
        var file = form.Files.GetFile(name);
        if (file is not null)
        {
            using var ms = new MemoryStream();
            await file.CopyToAsync(ms);
            return ms.ToArray();
        }

        return form.TryGetValue(name, out var v) ? Encoding.UTF8.GetBytes(v.ToString())
            : throw new ProtocolException(ErrorCodes.Request, $"Falta la parte {name}.");
    }

    private IResult Problem(string code, string detail)
    {
        var def = ErrorCodes.Get(code);
        return Results.Json(new ProblemDocument
        {
            Type = ProtocolConstants.ErrorTypeBase + code,
            Title = def.Title,
            Status = def.HttpStatus,
            Code = code,
            Detail = detail,
            NodeId = NodeId,
            TimestampUtc = Identifiers.FormatTimestamp(DateTimeOffset.UtcNow),
        }, statusCode: def.HttpStatus, contentType: ProtocolConstants.ProblemContentType);
    }

    public async ValueTask DisposeAsync()
    {
        if (app is not null)
        {
            await app.StopAsync();
            await app.DisposeAsync();
        }

        Identity.Dispose();
    }

    private sealed class MemoryReplay : IReplayGuard
    {
        public Task<bool> HasSeenAsync(string kind, string id, CancellationToken ct) => Task.FromResult(false);

        public Task<bool> TryMarkSeenAsync(string kind, string id, CancellationToken ct) => Task.FromResult(true);
    }

    private sealed class NoTrust : ITrustLookup
    {
        public Task<string?> GetPinnedThumbprintAsync(string nodeId, CancellationToken ct) => Task.FromResult<string?>(null);
    }
}
