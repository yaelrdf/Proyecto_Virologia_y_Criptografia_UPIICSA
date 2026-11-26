using System.Security.Cryptography.X509Certificates;
using CentroCiber.Packaging;

namespace CentroCiber.Application.Providers;

/// <summary>Petición <c>forward</c> independiente de si se ejecuta local o remotamente.</summary>
public sealed record ForwardRequest
{
    public required string AlgorithmCode { get; init; }

    public required byte[] Payload { get; init; }

    public required string PayloadMode { get; init; }

    public required string OriginalFileName { get; init; }

    public string? ContentType { get; init; }

    /// <summary>Imagen portadora (solo <c>LSBSTEGO</c>).</summary>
    public byte[]? Cover { get; init; }

    public IReadOnlyDictionary<string, string> Options { get; init; } = new Dictionary<string, string>();

    public IReadOnlyDictionary<string, string> Secrets { get; init; } = new Dictionary<string, string>();

    public string? KeyId { get; init; }

    /// <summary>Petición <c>/api/crypto/*</c> que originó la operación (nulo si es local desde la interfaz).</summary>
    public string? RequestId { get; init; }
}

/// <summary>Petición <c>inverse</c> sobre un paquete <c>package</c> ya validado.</summary>
public sealed record InverseRequest
{
    public required string AlgorithmCode { get; init; }

    public required byte[] PackageZip { get; init; }

    public IReadOnlyDictionary<string, string> Options { get; init; } = new Dictionary<string, string>();

    public IReadOnlyDictionary<string, string> Secrets { get; init; } = new Dictionary<string, string>();

    public string? RequestId { get; init; }

    /// <summary>Destinatario del <c>resultEnvelope</c>; nulo = este mismo nodo.</summary>
    public X509Certificate2? RecipientCertificate { get; init; }

    public string? RecipientNode { get; init; }
}

/// <summary>Resultado de una operación: el zip v2.0 producido (o un trabajo pendiente si es remoto asíncrono).</summary>
public sealed record OperationResult
{
    public byte[]? Zip { get; init; }

    public string? FileName { get; init; }

    public Manifest? Manifest { get; init; }

    /// <summary>Original descifrado del <c>result</c> cuando el destinatario es este nodo.</summary>
    public byte[]? Original { get; init; }

    /// <summary><c>jobId</c> remoto cuando el proveedor respondió <c>202</c>.</summary>
    public string? PendingJobId { get; init; }

    /// <summary><c>requestId</c> de la petición pendiente (para consultar el trabajo después).</summary>
    public string? PendingRequestId { get; init; }

    public string? ProviderNode { get; init; }

    public bool IsPending => PendingJobId is not null;
}

/// <summary>
/// Contrato común de algoritmos (plan §3.2): todo algoritmo, propio o ajeno, se usa con
/// <c>forward</c>/<c>inverse</c> y devuelve un paquete v2.0 idéntico en formato (§11.5).
/// </summary>
public interface IAlgorithmProvider
{
    bool CanHandle(string algorithmCode);

    Task<OperationResult> ForwardAsync(ForwardRequest request, CancellationToken ct);

    Task<OperationResult> InverseAsync(InverseRequest request, CancellationToken ct);
}
