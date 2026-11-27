using System.Collections.Frozen;

namespace CentroCiber.Crypto.Protocol;

/// <summary>Entrada del catálogo de errores (Anexo B).</summary>
public sealed record ErrorDefinition(string Code, int HttpStatus, string Title);

/// <summary>Catálogo de códigos de error del Anexo B del estándar v2.0.</summary>
public static class ErrorCodes
{
    public const string Size = "E-SIZE";
    public const string ZipInvalid = "E-ZIP-INVALID";
    public const string ZipStructure = "E-ZIP-STRUCTURE";
    public const string ZipBomb = "E-ZIP-BOMB";
    public const string Manifest = "E-MANIFEST";
    public const string Version = "E-VERSION";
    public const string Algorithm = "E-ALGORITHM";
    public const string Params = "E-PARAMS";
    public const string Request = "E-REQUEST";
    public const string RequestSignature = "E-REQUEST-SIGNATURE";
    public const string EnvRecipient = "E-ENV-RECIPIENT";
    public const string EnvDecrypt = "E-ENV-DECRYPT";
    public const string CertUntrusted = "E-CERT-UNTRUSTED";
    public const string AlgorithmNotProvided = "E-ALGORITHM-NOT-PROVIDED";
    public const string KeyNotFound = "E-KEY-NOT-FOUND";
    public const string KeyForbidden = "E-KEY-FORBIDDEN";
    public const string JobNotFound = "E-JOB-NOT-FOUND";
    public const string Duplicate = "E-DUPLICATE";
    public const string UnsupportedMedia = "E-UNSUPPORTED-MEDIA";
    public const string Hash = "E-HASH";
    public const string ParamsHash = "E-PARAMS-HASH";
    public const string Cert = "E-CERT";
    public const string CertThumbprint = "E-CERT-THUMBPRINT";
    public const string Signature = "E-SIGNATURE";
    public const string Timestamp = "E-TIMESTAMP";
    public const string VerifyFailed = "E-VERIFY-FAILED";
    public const string Internal = "E-INTERNAL";
    public const string Busy = "E-BUSY";
    public const string Timeout = "E-TIMEOUT";

    public static readonly FrozenDictionary<string, ErrorDefinition> Catalog = new ErrorDefinition[]
    {
        new(Size, 413, "Tamaño excedido"),
        new(ZipInvalid, 400, "Zip inválido"),
        new(ZipStructure, 400, "Estructura del zip inválida"),
        new(ZipBomb, 400, "Zip con descompresión excesiva"),
        new(Manifest, 400, "Manifiesto inválido"),
        new(Version, 400, "Versión no soportada"),
        new(Algorithm, 400, "Algoritmo inválido"),
        new(Params, 400, "Parámetros inválidos"),
        new(Request, 400, "Petición mal formada"),
        new(RequestSignature, 401, "Firma de la petición inválida"),
        new(EnvRecipient, 401, "Sobre dirigido a otro nodo"),
        new(EnvDecrypt, 401, "Sobre ilegible"),
        new(CertUntrusted, 403, "Certificado no confiable"),
        new(AlgorithmNotProvided, 404, "Algoritmo no provisto"),
        new(KeyNotFound, 404, "Llave no encontrada"),
        new(KeyForbidden, 403, "Llave no permitida"),
        new(JobNotFound, 404, "Trabajo no encontrado"),
        new(Duplicate, 409, "Identificador repetido"),
        new(UnsupportedMedia, 415, "Tipo de contenido no soportado"),
        new(Hash, 422, "Integridad inválida"),
        new(ParamsHash, 422, "Hash de parámetros inválido"),
        new(Cert, 422, "Certificado inválido"),
        new(CertThumbprint, 422, "Huella del certificado inválida"),
        new(Signature, 422, "Firma del manifiesto inválida"),
        new(Timestamp, 422, "Marca de tiempo fuera de ventana"),
        new(VerifyFailed, 422, "Verificación fallida"),
        new(Internal, 500, "Error interno"),
        new(Busy, 503, "Nodo ocupado"),
        new(Timeout, 504, "Tiempo agotado"),
    }.ToFrozenDictionary(e => e.Code, StringComparer.Ordinal);

    public static ErrorDefinition Get(string code) =>
        Catalog.TryGetValue(code, out var def) ? def : Catalog[Internal];
}
