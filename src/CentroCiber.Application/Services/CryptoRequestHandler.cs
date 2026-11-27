
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using CentroCiber.Application.Jobs;
using CentroCiber.Application.Providers;
using CentroCiber.Crypto.Envelope;
using CentroCiber.Crypto.Identity;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Crypto.Signing;
using CentroCiber.Infrastructure.Data.Entities;
using CentroCiber.Packaging;
using CentroCiber.Packaging.Contracts;

namespace CentroCiber.Application.Services;

/// <summary>Partes del <c>multipart/form-data</c> de <c>/api/crypto/*</c> (§10.6).</summary>
public sealed record IncomingCryptoRequest
{
    public required string Operation { get; init; }

    public byte[]? RequestBytes { get; init; }

    public string? RequestSignature { get; init; }

    public string? RequesterCertificatePem { get; init; }

    public byte[]? Payload { get; init; }

    public byte[]? Cover { get; init; }

    public byte[]? Package { get; init; }

    public string? RemoteIp { get; init; }
}

/// <summary>Respuesta del proveedor: zip síncrono (200) o trabajo asíncrono (202).</summary>
public sealed record CryptoResponse(byte[]? Zip, string? FileName, JobAccepted? Job, string RequestId);

/// <summary>
/// Proveedor de <c>POST /api/crypto/forward</c> e <c>inverse</c>: aplica las 8 validaciones de §13.2
/// en orden, ejecuta con tope síncrono de 30 s y, si no alcanza, responde 202 con <c>jobId</c>.
/// </summary>
public sealed class CryptoRequestHandler(
    NodeContext node,
    LocalAlgorithmProvider local,
    PackageValidator validator,
    IReplayGuard replay,
    NodeDirectory directory,
    JobQueue jobs,
    AuditService audit,
    Notifications.NotificationHub hub)
{
    public const string SeenKindRequest = "request";

    public async Task<CryptoResponse> HandleAsync(IncomingCryptoRequest incoming, CancellationToken ct)
    {
        var forward = incoming.Operation == ProtocolConstants.OperationForward;

        // Partes obligatorias
        if (incoming.RequestBytes is null || string.IsNullOrWhiteSpace(incoming.RequestSignature)
            || string.IsNullOrWhiteSpace(incoming.RequesterCertificatePem)
            || (forward ? incoming.Payload is null : incoming.Package is null))
        {
            throw new ProtocolException(ErrorCodes.Request,
                forward ? "Faltan partes: request, requestSignature, requesterCertificate y payload son obligatorias."
                        : "Faltan partes: request, requestSignature, requesterCertificate y package son obligatorias.");
        }

        // §13.2 #1: tamaño y, en inverse, las validaciones de §13.1 sobre el paquete (ADR 0005).
        if ((incoming.Payload?.LongLength ?? 0) + (incoming.Cover?.LongLength ?? 0) > ProtocolConstants.MaxBodyBytes)
        {
            throw new ProtocolException(ErrorCodes.Size, "El contenido supera 50 MB.");
        }

        ValidatedPackage? package = null;
        if (!forward)
        {
            package = await validator.ValidateAsync(incoming.Package!, PackageValidationOptions.ForInverse, ct);
        }

        var request = ParseRequest(incoming.RequestBytes, incoming.Operation);

        // §13.2 #2: certificado del solicitante, CN = requesterNode, huella fijada o confirmable.
        X509Certificate2 requesterCert = CertificateTools.LoadAndValidate(incoming.RequesterCertificatePem!, request.RequesterNode, node.Clock.GetUtcNow());
        var thumbprint = CertificateTools.Thumbprint(requesterCert);
        var pinned = await directory.GetPinnedThumbprintAsync(request.RequesterNode, ct);
        if (pinned is not null && !string.Equals(pinned, thumbprint, StringComparison.Ordinal))
        {
            throw new ProtocolException(ErrorCodes.CertUntrusted, $"La huella de {request.RequesterNode} no coincide con la fijada.");
        }

        // §13.2 #3: firma sobre los bytes exactos de la parte request.
        if (!RsaPss.Verify(requesterCert, incoming.RequestBytes, incoming.RequestSignature))
        {
            throw new ProtocolException(ErrorCodes.RequestSignature, "La firma de la petición no es válida.");
        }

        // §13.2 #4
        if (!string.Equals(request.TargetNode, node.NodeId, StringComparison.Ordinal))
        {
            throw new ProtocolException(ErrorCodes.Request, $"La petición es para {request.TargetNode}, no para {node.NodeId}.");
        }

        // §13.2 #5
        PackageValidator.CheckTimestamp(request.TimestampUtc, node.Clock);
        if (!await replay.TryMarkSeenAsync(SeenKindRequest, request.RequestId, ct))
        {
            throw new ProtocolException(ErrorCodes.Duplicate, "El requestId ya fue recibido.");
        }

        // ADR 0006: solicitante no fijado → se acepta y queda pendiente de confirmar en el directorio.
        if (pinned is null)
        {
            await directory.RegisterRequesterAsync(request.RequesterNode, incoming.RemoteIp, incoming.RequesterCertificatePem!, thumbprint, ct);
        }

        // §13.2 #6
        if (AlgorithmCatalog.ByCode(request.AlgorithmCode) is null)
        {
            throw new ProtocolException(ErrorCodes.Algorithm, $"Algoritmo desconocido: {request.AlgorithmCode}.");
        }

        if (!local.CanHandle(request.AlgorithmCode))
        {
            throw new ProtocolException(ErrorCodes.AlgorithmNotProvided, $"{node.NodeId} no provee {request.AlgorithmCode}.");
        }

        if (package is not null && package.Manifest.AlgorithmCode != request.AlgorithmCode)
        {
            throw new ProtocolException(ErrorCodes.Request, "El algoritmo del paquete no coincide con el de la petición.");
        }

        // §13.2 #7
        var secrets = request.Secrets is null
            ? new Dictionary<string, string>()
            : EnvelopeCrypto.OpenSecrets(request.Secrets, node.Identity, request.RequestId);

        await audit.LogAsync("crypto." + incoming.Operation, request.RequesterNode, null, $"{request.AlgorithmCode} {request.RequestId}", ct);

        // §13.2 #8 (opciones y secretos según el perfil) se valida dentro del algoritmo → E-PARAMS.
        var options = request.Options ?? new Dictionary<string, string>();
        var work = Task.Run(async () =>
        {
            try
            {
                OperationResult result = forward
                    ? await local.ForwardAsync(new ForwardRequest
                    {
                        AlgorithmCode = request.AlgorithmCode,
                        Payload = incoming.Payload!,
                        PayloadMode = request.PayloadMode,
                        OriginalFileName = string.IsNullOrWhiteSpace(request.OriginalFileName) ? ProtocolConstants.DefaultTextFileName : request.OriginalFileName,
                        Cover = incoming.Cover,
                        Options = options,
                        Secrets = secrets,
                        KeyId = request.KeyId,
                        RequestId = request.RequestId,
                    }, CancellationToken.None)
                    : await local.InverseValidatedAsync(package!, new InverseRequest
                    {
                        AlgorithmCode = request.AlgorithmCode,
                        PackageZip = incoming.Package!,
                        Options = options,
                        Secrets = secrets,
                        RequestId = request.RequestId,
                        RecipientCertificate = requesterCert,
                        RecipientNode = request.RequesterNode,
                    }, CancellationToken.None);
                return (result.Zip!, result.FileName!);
            }
            finally
            {
                // §10.6 #5: descartar secretos de memoria.
                foreach (var key in secrets.Keys.ToList())
                {
                    secrets[key] = string.Empty;
                }
            }
        }, CancellationToken.None);

        var timeout = TimeSpan.FromSeconds(node.Options.SyncTimeoutSeconds);
        if (timeout > TimeSpan.Zero && await Task.WhenAny(work, Task.Delay(timeout, ct)) == work)
        {
            var (zip, name) = await work;
            return new CryptoResponse(zip, name, null, request.RequestId);
        }

        var job = jobs.Track(request.RequesterNode, request.RequestId, work, j =>
            hub.Publish(new Notifications.NodeEvent(Notifications.NodeEventKind.JobCompleted,
                $"Trabajo {j.JobId} para {j.RequesterNode}: {j.State}", node.Clock.GetUtcNow(), j.RequesterNode)));
        await directory.RecordOperationAsync(new RemoteOperationEntity
        {
            RequestId = request.RequestId,
            Direction = OperationDirections.Incoming,
            PeerNode = request.RequesterNode,
            AlgorithmCode = request.AlgorithmCode,
            Operation = incoming.Operation,
            JobId = job.JobId,
            State = ProtocolConstants.JobRunning,
        }, ct);
        return new CryptoResponse(null, null,
            new JobAccepted(job.JobId, $"/api/jobs/{job.JobId}", ProtocolConstants.JobRetryAfterSeconds), request.RequestId);
    }

    /// <summary>Lee y valida el objeto <c>request</c>; errores → <c>E-REQUEST</c> / <c>E-VERSION</c>.</summary>
    public static CryptoRequest ParseRequest(byte[] bytes, string operation)
    {
        CryptoRequest? request;
        try
        {
            request = JsonSerializer.Deserialize<CryptoRequest>(bytes, ProtocolJson.Options);
        }
        catch (JsonException ex)
        {
            throw new ProtocolException(ErrorCodes.Request, "La parte request no es JSON válido o le faltan campos.", ex);
        }

        if (request is null)
        {
            throw new ProtocolException(ErrorCodes.Request, "La parte request está vacía.");
        }

        if (request.Version != ProtocolConstants.ProtocolVersion)
        {
            throw new ProtocolException(ErrorCodes.Version, $"Versión de protocolo no soportada: {request.Version}.");
        }

        var bad = new List<string>();
        if (!Identifiers.IsUuidV4(request.RequestId))
        {
            bad.Add("requestId");
        }

        if (!Identifiers.IsNodeId(request.RequesterNode))
        {
            bad.Add("requesterNode");
        }

        if (!Identifiers.IsNodeId(request.TargetNode))
        {
            bad.Add("targetNode");
        }

        if (!Identifiers.IsTimestamp(request.TimestampUtc))
        {
            bad.Add("timestampUtc");
        }

        if (request.Operation != operation)
        {
            bad.Add("operation");
        }

        if (request.PayloadMode is not (ProtocolConstants.PayloadText or ProtocolConstants.PayloadFile
            or ProtocolConstants.PayloadImage or ProtocolConstants.PayloadMultipart))
        {
            bad.Add("payloadMode");
        }

        if (request.Options?.Values.Any(v => v is null) == true)
        {
            bad.Add("options");
        }

        if (bad.Count > 0)
        {
            throw new ProtocolException(ErrorCodes.Request, "Campos inválidos en request: " + string.Join(", ", bad) + ".");
        }

        return request;
    }

}
