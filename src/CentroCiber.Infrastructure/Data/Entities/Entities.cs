namespace CentroCiber.Infrastructure.Data.Entities;

/// <summary>Diccionario 4.1 (tabla <c>Algorithms</c>).</summary>
public class AlgorithmEntity
{
    public int Id { get; set; }

    public required string Code { get; set; }

    public required string Name { get; set; }

    public required string Category { get; set; }

    public int? OwnerTeam { get; set; }

    public required string ForwardName { get; set; }

    public required string InverseName { get; set; }

    public required string KeyKind { get; set; }
}

/// <summary>Equipos del Centro (tabla <c>Teams</c>).</summary>
public class TeamEntity
{
    public int TeamNumber { get; set; }

    public required string NodeId { get; set; }

    public int HttpPort { get; set; }

    public int HttpsPort { get; set; }

    /// <summary>Códigos de algoritmo separados por coma.</summary>
    public required string AlgorithmCodes { get; set; }
}

/// <summary>Estado de confianza de un nodo del directorio (§6.3).</summary>
public static class TrustStates
{
    public const string Self = "Propio";
    public const string Pending = "PendienteConfirmar";
    public const string Pinned = "Confirmado";
    public const string ThumbprintChanged = "HuellaCambiada";
    public const string Invalid = "Inválido";
}

/// <summary>Origen del alta en el directorio (§6.4).</summary>
public static class NodeSources
{
    public const string Beacon = "beacon";
    public const string Scan = "scan";
    public const string Manual = "manual";
    public const string Request = "request";
}

/// <summary>Directorio de nodos (§6.4, tabla <c>Nodes</c>).</summary>
public class NodeEntity
{
    public int Id { get; set; }

    public required string NodeId { get; set; }

    public int TeamNumber { get; set; }

    public required string Ip { get; set; }

    public int HttpPort { get; set; }

    public int? HttpsPort { get; set; }

    /// <summary>Huella confirmada por el usuario (TOFU).</summary>
    public string? PinnedThumbprintSha256 { get; set; }

    /// <summary>Última huella observada (anuncio o certificado).</summary>
    public string? ObservedThumbprintSha256 { get; set; }

    public string? CertificatePem { get; set; }

    /// <summary>Códigos anunciados, separados por coma.</summary>
    public string Algorithms { get; set; } = string.Empty;

    public required string Source { get; set; }

    public required string Status { get; set; }

    public required string TrustState { get; set; }

    public bool IsSelf { get; set; }

    public DateTime? LastSeenUtc { get; set; }

    /// <summary>Perfil <c>GET /api/algorithms</c> en caché (JSON).</summary>
    public string? ProfileJson { get; set; }

    public string? LastError { get; set; }
}

/// <summary>Orígenes de Consultas (§15).</summary>
public static class PackageOrigins
{
    public const string Generated = "Generado";
    public const string Received = "Recibido";
    public const string Result = "Resultado";
}

/// <summary>Consultas: paquetes y resultados guardados (tabla <c>Packages</c>).</summary>
public class PackageEntity
{
    public int Id { get; set; }

    public required string PacketId { get; set; }

    public required string FileName { get; set; }

    public required string Origin { get; set; }

    public required string PacketType { get; set; }

    public required string AlgorithmCode { get; set; }

    public required string Operation { get; set; }

    public required string SourceNode { get; set; }

    public required string ProducerNode { get; set; }

    public string? RequestId { get; set; }

    public required string EncryptedSha256 { get; set; }

    public string? KeyId { get; set; }

    public string? KeyOwnerNode { get; set; }

    public string? OriginalFileName { get; set; }

    /// <summary>Ruta relativa a la carpeta de paquetes; nulo en registros de ejemplo.</summary>
    public string? StoragePath { get; set; }

    public long SizeBytes { get; set; }

    public required string ManifestJson { get; set; }

    public bool? VerificationValid { get; set; }

    public string? VerificationDetail { get; set; }

    public bool IsSample { get; set; }

    public DateTime CreatedUtc { get; set; }
}

/// <summary>Estados de la bandeja (§15).</summary>
public static class RequestStates
{
    public const string Pending = "Pendiente";
    public const string Accepted = "Aceptada";
    public const string Rejected = "Rechazada";
}

/// <summary>Resultado de validación mostrado en Solicitudes (§15).</summary>
public static class ValidationLabels
{
    public const string SignatureOk = "Firma OK";
    public const string Invalid = "Inválida";
    public const string Unconfirmed = "Remitente no confirmado";
}

/// <summary>Bandeja de Solicitudes (tabla <c>Requests</c>).</summary>
public class InboxRequestEntity
{
    public int Id { get; set; }

    public required string PacketId { get; set; }

    public required string SourceNode { get; set; }

    public required string SourceIp { get; set; }

    public required string FileName { get; set; }

    public required string AlgorithmCode { get; set; }

    public required string OperationName { get; set; }

    public required string ValidationResult { get; set; }

    public required string Status { get; set; }

    public string? ErrorCode { get; set; }

    public string? StoragePath { get; set; }

    public string? ManifestJson { get; set; }

    public int? PackageId { get; set; }

    public bool IsSample { get; set; }

    public DateTime ReceivedUtc { get; set; }

    public DateTime? DecidedUtc { get; set; }
}

/// <summary>Direcciones de una operación remota.</summary>
public static class OperationDirections
{
    public const string Outgoing = "Saliente";
    public const string Incoming = "Entrante";
}

/// <summary>Peticiones <c>/api/crypto/*</c> enviadas y recibidas (tabla <c>RemoteOperations</c>).</summary>
public class RemoteOperationEntity
{
    public int Id { get; set; }

    public required string RequestId { get; set; }

    public required string Direction { get; set; }

    public required string PeerNode { get; set; }

    public required string AlgorithmCode { get; set; }

    public required string Operation { get; set; }

    public string? JobId { get; set; }

    public required string State { get; set; }

    public string? ErrorCode { get; set; }

    public string? ErrorDetail { get; set; }

    public int? ResultPackageId { get; set; }

    public DateTime CreatedUtc { get; set; }

    public DateTime UpdatedUtc { get; set; }
}

/// <summary>Identificadores ya vistos para anti-repetición (§13.1 #14, §13.2 #5).</summary>
public class SeenIdEntity
{
    public required string Id { get; set; }

    /// <summary><c>packet</c> o <c>request</c>.</summary>
    public required string Kind { get; set; }

    public DateTime SeenUtc { get; set; }
}

/// <summary>Ajustes del nodo (tabla <c>Settings</c>, una fila).</summary>
public class SettingsEntity
{
    public int Id { get; set; }

    /// <summary>Variantes habilitadas separadas por coma.</summary>
    public required string EnabledVariants { get; set; }

    public bool HttpsEnabled { get; set; }

    public bool AcceptingPackages { get; set; }

    public long MaxPayloadBytes { get; set; }

    public required string PfxFileName { get; set; }
}

/// <summary>Bitácora sin secretos (tabla <c>AuditLog</c>).</summary>
public class AuditLogEntity
{
    public long Id { get; set; }

    public DateTime TimestampUtc { get; set; }

    public required string Event { get; set; }

    public string? NodeId { get; set; }

    public string? Code { get; set; }

    public string? Detail { get; set; }
}
