using System.Net;
using System.Net.Http.Headers;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using CentroCiber.Application.Services;
using CentroCiber.Crypto.Envelope;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Infrastructure.Data.Entities;
using CentroCiber.Infrastructure.Http;
using CentroCiber.Packaging;
using CentroCiber.Packaging.Client;
using CentroCiber.Packaging.Contracts;

namespace CentroCiber.Application.Providers;

/// <summary>Disponibilidad de un algoritmo para la interfaz (§11.6).</summary>
public sealed record ProviderAvailability(AlgorithmInfo Algorithm, string? ProviderNode, bool IsLocal, bool Available, string Reason);

/// <summary>El dueño del algoritmo no se puede usar (fuera de línea, sin confirmar, sin proveedor…).</summary>
public sealed class ProviderUnavailableException(string message) : Exception(message)
{
    public ProviderUnavailableException()
        : this("Proveedor no disponible.")
    {
    }

    public ProviderUnavailableException(string message, Exception inner)
        : this(message + " " + inner.Message)
    {
    }
}

/// <summary>
/// Proveedor remoto (plan §3.2): elige al dueño del algoritmo, firma la petición, cifra los secretos
/// para él (§8.3), envía <c>/api/crypto/*</c> y maneja <c>200</c>, <c>202</c> (consulta de <c>jobId</c>)
/// y <c>problem+json</c>. Todo paquete recibido se valida con §13.1.
/// </summary>
public sealed class RemoteAlgorithmProvider(
    NodeContext node,
    NodeDirectory directory,
    NodeHttpClientFactory httpFactory,
    PackageValidator validator,
    AuditService audit)
{
    /// <summary>Tiempo máximo esperando un trabajo asíncrono antes de devolverlo como pendiente.</summary>
    public TimeSpan JobWait { get; init; } = TimeSpan.FromMinutes(2);

    /// <summary>§4.4: preferir al dueño de la tabla 4.1; para reservados, el <c>teamNumber</c> menor.</summary>
    public async Task<ProviderAvailability> GetAvailabilityAsync(AlgorithmInfo info, CancellationToken ct = default)
    {
        if (info.OwnerTeam == node.TeamNumber)
        {
            return new ProviderAvailability(info, node.NodeId, true, true, "Algoritmo propio (local).");
        }

        var nodes = (await directory.ListAsync(ct)).Where(n => !n.IsSelf).ToList();
        var announcing = nodes.Where(n => n.Algorithms.Split(',').Contains(info.Code, StringComparer.Ordinal)).ToList();
        NodeEntity? candidate = info.OwnerNodeId is { } owner
            ? nodes.FirstOrDefault(n => n.NodeId == owner) ?? announcing.OrderBy(n => n.TeamNumber).FirstOrDefault()
            : announcing.Where(Usable).OrderBy(n => n.TeamNumber).FirstOrDefault() ?? announcing.OrderBy(n => n.TeamNumber).FirstOrDefault();

        if (candidate is null)
        {
            return new ProviderAvailability(info, info.OwnerNodeId, false, false, info.OwnerNodeId is null
                ? "Sin proveedor: ningún nodo anuncia este algoritmo reservado."
                : $"{info.OwnerNodeId} no está en el directorio. Búscalo en Nodos o dalo de alta manualmente.");
        }

        var reason = candidate.Status != ProtocolConstants.StatusOnline ? $"{candidate.NodeId} está fuera de línea."
            : candidate.TrustState == TrustStates.ThumbprintChanged ? $"La huella de {candidate.NodeId} cambió; acéptala de nuevo en Nodos."
            : candidate.TrustState != TrustStates.Pinned ? $"Confirma la huella de {candidate.NodeId} en Nodos (TOFU)."
            : !candidate.Algorithms.Split(',').Contains(info.Code, StringComparer.Ordinal) ? $"{candidate.NodeId} no anuncia {info.Code}."
            : candidate.CertificatePem is null ? $"Falta el certificado de {candidate.NodeId}."
            : $"Disponible en {candidate.NodeId}.";
        return new ProviderAvailability(info, candidate.NodeId, false, Usable(candidate) && candidate.Algorithms.Split(',').Contains(info.Code, StringComparer.Ordinal), reason);
    }

    public async Task<OperationResult> ForwardAsync(ForwardRequest request, CancellationToken ct)
    {
        var owner = await RequireOwnerAsync(request.AlgorithmCode, ct);
        using var ownerCert = X509Certificate2.CreateFromPem(owner.CertificatePem!);
        var signed = CryptoRequestBuilder.Create(node.Identity, new CryptoRequestSpec
        {
            TargetNode = owner.NodeId,
            TargetCertificate = ownerCert,
            AlgorithmCode = request.AlgorithmCode,
            Operation = ProtocolConstants.OperationForward,
            PayloadMode = request.PayloadMode,
            OriginalFileName = request.OriginalFileName,
            Options = request.Options,
            Secrets = request.Secrets,
            KeyId = request.KeyId,
        }, node.Clock);
        using var content = signed.ToMultipart(request.Payload, request.OriginalFileName, request.Cover);
        var (zip, jobId) = await SendAsync(owner, "/api/crypto/forward", signed.Request, content, ct);
        if (zip is null)
        {
            return new OperationResult { PendingJobId = jobId, PendingRequestId = signed.Request.RequestId, ProviderNode = owner.NodeId };
        }

        var package = await ValidateResponseAsync(zip, owner.NodeId, ProtocolConstants.PacketTypePackage, signed.Request.RequestId, ct);
        await directory.UpdateOperationAsync(signed.Request.RequestId, ProtocolConstants.JobDone, null, null, null, null, ct);
        return new OperationResult { Zip = zip, FileName = PackageNaming.FileName(package.Manifest), Manifest = package.Manifest, ProviderNode = owner.NodeId };
    }

    public async Task<OperationResult> InverseAsync(InverseRequest request, CancellationToken ct)
    {
        var owner = await RequireOwnerAsync(request.AlgorithmCode, ct);
        using var ownerCert = X509Certificate2.CreateFromPem(owner.CertificatePem!);
        var source = await validator.ValidateAsync(request.PackageZip, PackageValidationOptions.ForInverse, ct);
        var signed = CryptoRequestBuilder.Create(node.Identity, new CryptoRequestSpec
        {
            TargetNode = owner.NodeId,
            TargetCertificate = ownerCert,
            AlgorithmCode = request.AlgorithmCode,
            Operation = ProtocolConstants.OperationInverse,
            PayloadMode = source.Manifest.PayloadMode,
            OriginalFileName = source.Manifest.OriginalFileName,
            Options = request.Options,
            Secrets = request.Secrets,
            KeyId = source.Manifest.KeyRef?.KeyId,
        }, node.Clock);
        using var content = signed.ToMultipart(packageZip: request.PackageZip);
        var (zip, jobId) = await SendAsync(owner, "/api/crypto/inverse", signed.Request, content, ct);
        if (zip is null)
        {
            return new OperationResult { PendingJobId = jobId, PendingRequestId = signed.Request.RequestId, ProviderNode = owner.NodeId };
        }

        return await CompleteInverseAsync(zip, owner.NodeId, signed.Request.RequestId, ct);
    }

    /// <summary>Valida un <c>result</c> y abre su <c>resultEnvelope</c> con la llave propia (§11.4).</summary>
    public async Task<OperationResult> CompleteInverseAsync(byte[] zip, string ownerNode, string requestId, CancellationToken ct)
    {
        var result = await ValidateResponseAsync(zip, ownerNode, ProtocolConstants.PacketTypeResult, requestId, ct);
        var envelope = result.Manifest.ResultEnvelope
            ?? throw new ProtocolException(ErrorCodes.Manifest, "El resultado no trae resultEnvelope.");
        var original = EnvelopeCrypto.OpenDetached(envelope, result.Data, node.Identity, result.Manifest.PacketId);
        await directory.UpdateOperationAsync(requestId, ProtocolConstants.JobDone, null, null, null, null, ct);
        return new OperationResult
        {
            Zip = zip,
            FileName = PackageNaming.FileName(result.Manifest),
            Manifest = result.Manifest,
            Original = original,
            ProviderNode = ownerNode,
        };
    }

    /// <summary>Consulta un trabajo pendiente y descarga su resultado si ya terminó (§10.7).</summary>
    public async Task<byte[]?> TryFetchJobAsync(string ownerNode, string jobId, string requestId, CancellationToken ct)
    {
        var owner = await directory.FindAsync(ownerNode, ct) ?? throw new ProviderUnavailableException($"{ownerNode} ya no está en el directorio.");
        using var http = CreateClient(owner, out var baseUri);
        using var statusMsg = Message(HttpMethod.Get, new Uri(baseUri, $"/api/jobs/{jobId}"), requestId);
        using var statusResponse = await http.SendAsync(statusMsg, ct);
        await ThrowIfProblemAsync(statusResponse, owner.NodeId, ct);
        var status = JsonSerializer.Deserialize<JobStatusResponse>(await statusResponse.Content.ReadAsStringAsync(ct))!;
        if (status.State == ProtocolConstants.JobFailed)
        {
            await directory.UpdateOperationAsync(requestId, ProtocolConstants.JobFailed, jobId, status.Error?.Code, status.Error?.Detail, null, ct);
            throw new ProtocolException(status.Error?.Code ?? ErrorCodes.Internal, $"{owner.NodeId}: {status.Error?.Detail ?? "el trabajo falló."}");
        }

        if (status.State != ProtocolConstants.JobDone)
        {
            return null;
        }

        using var resultMsg = Message(HttpMethod.Get, new Uri(baseUri, status.ResultUrl ?? $"/api/jobs/{jobId}/result"), requestId);
        using var resultResponse = await http.SendAsync(resultMsg, ct);
        await ThrowIfProblemAsync(resultResponse, owner.NodeId, ct);
        return await resultResponse.Content.ReadAsByteArrayAsync(ct);
    }

    /// <summary>Envía un paquete a la bandeja de otro nodo (§11.3), re-firmado (§9.6).</summary>
    public async Task<ReceiveResponse> SendToInboxAsync(string targetNode, byte[] zip, CancellationToken ct)
    {
        var target = await directory.FindAsync(targetNode, ct) ?? throw new ProviderUnavailableException($"{targetNode} no está en el directorio.");
        if (!Usable(target))
        {
            throw new ProviderUnavailableException($"{targetNode} no está disponible (en línea y con huella confirmada).");
        }

        var original = await validator.ValidateAsync(zip, PackageValidationOptions.ForInverse with { ExpectedPacketType = null }, ct);
        var forwarded = PackageForwarder.Forward(original, node.Identity, node.SourceIp, node.Clock);
        using var http = CreateClient(target, out var baseUri);
        using var content = new MultipartFormDataContent();
        var file = new ByteArrayContent(forwarded.Zip);
        file.Headers.ContentType = new MediaTypeHeaderValue(ProtocolConstants.ZipContentType);
        content.Add(file, ProtocolConstants.PartPackage, forwarded.FileName);
        using var msg = Message(HttpMethod.Post, new Uri(baseUri, "/api/requests/receive"), forwarded.Manifest.PacketId);
        msg.Content = content;
        HttpResponseMessage response;
        try
        {
            response = await SendWithTlsHandlingAsync(http, msg, target.NodeId, ct);
            await ThrowIfProblemAsync(response, target.NodeId, ct);
        }
        catch (ProtocolException ex)
        {
            await audit.LogAsync(AuditService.EventDelegateError, targetNode, ex.Code, "Envío a bandeja: " + ex.Message, ct);
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            await audit.LogAsync(AuditService.EventDelegateError, targetNode, ErrorCodes.Timeout, "Envío a bandeja: " + ex.Message, ct);
            throw new ProviderUnavailableException($"No se pudo contactar a {targetNode}: {ex.Message}");
        }

        using var _ = response;
        await audit.LogAsync(AuditService.EventOutboxSent, targetNode, null, $"{forwarded.Manifest.AlgorithmCode} {forwarded.Manifest.PacketId}", ct);
        return JsonSerializer.Deserialize<ReceiveResponse>(await response.Content.ReadAsStringAsync(ct))!;
    }

    private static bool Usable(NodeEntity n) =>
        n.Status == ProtocolConstants.StatusOnline && n.TrustState == TrustStates.Pinned && n.CertificatePem is not null;

    private async Task<NodeEntity> RequireOwnerAsync(string code, CancellationToken ct)
    {
        var info = AlgorithmCatalog.ByCode(code) ?? throw new ProtocolException(ErrorCodes.Algorithm, $"Algoritmo desconocido: {code}.");
        var availability = await GetAvailabilityAsync(info, ct);
        if (!availability.Available || availability.ProviderNode is null)
        {
            throw new ProviderUnavailableException($"{code} no disponible: {availability.Reason}");
        }

        return (await directory.FindAsync(availability.ProviderNode, ct))!;
    }

    private HttpClient CreateClient(NodeEntity target, out Uri baseUri)
    {
        // §5.2: si ambos ofrecen HTTPS, usarlo y validar la huella fijada.
        if (node.HttpsActive && target.HttpsPort is { } https && target.PinnedThumbprintSha256 is { } pin)
        {
            baseUri = new Uri($"https://{target.Ip}:{https}");
            return httpFactory.CreatePinned(pin);
        }

        baseUri = new Uri($"http://{target.Ip}:{target.HttpPort}");
        return httpFactory.CreatePlain();
    }

    private HttpRequestMessage Message(HttpMethod method, Uri uri, string requestId)
    {
        var msg = new HttpRequestMessage(method, uri);
        CryptoRequestBuilder.AddProtocolHeaders(msg, node.NodeId, requestId);
        return msg;
    }

    /// <summary>Devuelve el zip (200) o nulo si quedó un trabajo pendiente tras <see cref="JobWait"/>.</summary>
    private async Task<(byte[]? Zip, string? JobId)> SendAsync(NodeEntity owner, string path, CryptoRequest request, HttpContent content, CancellationToken ct)
    {
        await directory.RecordOperationAsync(new RemoteOperationEntity
        {
            RequestId = request.RequestId,
            Direction = OperationDirections.Outgoing,
            PeerNode = owner.NodeId,
            AlgorithmCode = request.AlgorithmCode,
            Operation = request.Operation,
            State = ProtocolConstants.JobRunning,
        }, ct);
        await audit.LogAsync("delegate." + request.Operation, owner.NodeId, null, $"{request.AlgorithmCode} {request.RequestId}", ct);
        using var http = CreateClient(owner, out var baseUri);
        using var msg = Message(HttpMethod.Post, new Uri(baseUri, path), request.RequestId);
        msg.Content = content;
        try
        {
            using var response = await SendWithTlsHandlingAsync(http, msg, owner.NodeId, ct);
            if (response.StatusCode == HttpStatusCode.Accepted)
            {
                var job = JsonSerializer.Deserialize<JobAccepted>(await response.Content.ReadAsStringAsync(ct))
                    ?? throw new ProtocolException(ErrorCodes.Internal, "Respuesta 202 sin jobId.");
                await directory.UpdateOperationAsync(request.RequestId, ProtocolConstants.JobQueued, job.JobId, null, null, null, ct);
                return await WaitForJobAsync(owner.NodeId, job, request.RequestId, ct);
            }

            await ThrowIfProblemAsync(response, owner.NodeId, ct);
            return (await response.Content.ReadAsByteArrayAsync(ct), null);
        }
        catch (ProtocolException ex)
        {
            await directory.UpdateOperationAsync(request.RequestId, ProtocolConstants.JobFailed, null, ex.Code, ex.Message, null, ct);
            await audit.LogAsync(AuditService.EventDelegateError, owner.NodeId, ex.Code, ex.Message, ct);
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            await directory.UpdateOperationAsync(request.RequestId, ProtocolConstants.JobFailed, null, ErrorCodes.Timeout, ex.Message, null, ct);
            throw new ProviderUnavailableException($"No se pudo contactar a {owner.NodeId}: {ex.Message}");
        }
    }

    private async Task<(byte[]? Zip, string? JobId)> WaitForJobAsync(string ownerNode, JobAccepted job, string requestId, CancellationToken ct)
    {
        var deadline = node.Clock.GetUtcNow() + JobWait;
        var delay = TimeSpan.FromSeconds(Math.Clamp(job.RetryAfterSeconds, 1, 30));
        while (node.Clock.GetUtcNow() < deadline)
        {
            await Task.Delay(delay, ct);
            var zip = await TryFetchJobAsync(ownerNode, job.JobId, requestId, ct);
            if (zip is not null)
            {
                return (zip, job.JobId);
            }
        }

        return (null, job.JobId);
    }

    private static async Task<HttpResponseMessage> SendWithTlsHandlingAsync(HttpClient http, HttpRequestMessage msg, string nodeId, CancellationToken ct)
    {
        try
        {
            return await http.SendAsync(msg, ct);
        }
        catch (HttpRequestException ex) when (ex.InnerException is AuthenticationException)
        {
            throw new ProtocolException(ErrorCodes.CertUntrusted, $"El certificado TLS de {nodeId} no coincide con la huella fijada.", ex);
        }
    }

    private static async Task ThrowIfProblemAsync(HttpResponseMessage response, string nodeId, CancellationToken ct)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        var body = await response.Content.ReadAsStringAsync(ct);
        string code = ErrorCodes.Internal;
        var detail = $"HTTP {(int)response.StatusCode}";
        try
        {
            var problem = JsonSerializer.Deserialize<ProblemDocument>(body);
            if (problem is not null)
            {
                code = ErrorCodes.Catalog.ContainsKey(problem.Code) ? problem.Code : ErrorCodes.Internal;
                detail = problem.Detail;
            }
        }
        catch (JsonException)
        {
        }

        throw new ProtocolException(code, $"{nodeId} respondió {code}: {detail}");
    }

    private async Task<ValidatedPackage> ValidateResponseAsync(byte[] zip, string ownerNode, string expectedType, string requestId, CancellationToken ct)
    {
        var p = await validator.ValidateAsync(zip, PackageValidationOptions.Inbox with { ExpectedPacketType = expectedType }, ct);
        if (p.Manifest.SourceNode != ownerNode || p.Manifest.ProducerNode != ownerNode)
        {
            throw new ProtocolException(ErrorCodes.Cert, $"El paquete no fue producido por {ownerNode}.");
        }

        if (p.Manifest.RequestId is not null && p.Manifest.RequestId != requestId)
        {
            throw new ProtocolException(ErrorCodes.Request, "El paquete corresponde a otra petición.");
        }

        return p;
    }
}
