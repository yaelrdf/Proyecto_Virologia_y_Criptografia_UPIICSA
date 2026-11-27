using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using CentroCiber.Crypto.Identity;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Crypto.Signing;

namespace CentroCiber.Packaging;

/// <summary>Registro de identificadores vistos (§13.1 #14, §13.2 #5).</summary>
public interface IReplayGuard
{
    Task<bool> HasSeenAsync(string kind, string id, CancellationToken ct);

    /// <summary>Marca el id; devuelve falso si ya existía.</summary>
    Task<bool> TryMarkSeenAsync(string kind, string id, CancellationToken ct);
}

/// <summary>Consulta de huellas fijadas en el directorio (§6.3, §13.1 nota).</summary>
public interface ITrustLookup
{
    /// <summary>Huella fijada por el usuario para <paramref name="nodeId"/>, o nulo si no está fijado.</summary>
    Task<string?> GetPinnedThumbprintAsync(string nodeId, CancellationToken ct);
}

/// <summary>Opciones de validación de un paquete recibido.</summary>
public sealed record PackageValidationOptions
{
    /// <summary>§13.1 #13. Ver ADR 0005: en <c>inverse</c> se aplica a la petición, no al paquete.</summary>
    public bool CheckTimestamp { get; init; } = true;

    /// <summary>§13.1 #14. Ver ADR 0005.</summary>
    public bool CheckReplay { get; init; } = true;

    /// <summary>Si no es nulo, exige ese <c>packetType</c>.</summary>
    public string? ExpectedPacketType { get; init; }

    public static PackageValidationOptions Inbox { get; } = new();

    public static PackageValidationOptions ForInverse { get; } = new()
    {
        CheckTimestamp = false,
        CheckReplay = false,
        ExpectedPacketType = ProtocolConstants.PacketTypePackage,
    };
}

/// <summary>Paso de validación mostrado en la interfaz (“validación paso a paso”).</summary>
public sealed record ValidationStep(int Number, string Description, bool Passed, string? Code = null, string? Detail = null);

/// <summary>Paquete que pasó las validaciones.</summary>
public sealed record ValidatedPackage(
    byte[] Zip,
    Manifest Manifest,
    byte[] Data,
    string CertificatePem,
    X509Certificate2 Certificate,
    bool SenderPinned,
    IReadOnlyList<byte[]>? Parts,
    IReadOnlyList<string>? OmittedFields = null);

/// <summary>Reporte completo de validación (incluye el paso que falló).</summary>
public sealed record ValidationReport(IReadOnlyList<ValidationStep> Steps, ValidatedPackage? Package, ProtocolException? Error)
{
    public bool IsValid => Error is null;
}

/// <summary>
/// Las 14 validaciones de recepción de §13.1, en orden; se detiene en la primera que falla.
/// Después de la #13 se revisa la huella fijada (<c>E-CERT-UNTRUSTED</c>) y al final la #14,
/// que registra el <c>packetId</c> solo si todo lo anterior pasó.
/// </summary>
public sealed class PackageValidator(TimeProvider clock, IReplayGuard replay, ITrustLookup trust)
{
    public const string SeenKindPacket = "packet";

    /// <summary>
    /// Campos que DEBEN venir con valor: los de la cadena de firma §8.4 y la firma misma. Sin ellos no se puede
    /// verificar el paquete (ADR 0016).
    /// </summary>
    private static readonly string[] RequiredFields =
    [
        "version", "packetType", "packetId", "sourceNode", "producerNode", "algorithmCode", "operation",
        "timestampUtc", "encryptedSha256", "publicParametersSha256", "certificateThumbprintSha256", "manifestSignatureBase64",
    ];

    /// <summary>
    /// Campos informativos de §9.5 que no entran en la firma. Si otro nodo los omite se completan con un valor
    /// deducible y se informan como «omitidos» (ADR 0016). EQ08 siempre los envía.
    /// </summary>
    public static readonly IReadOnlyList<string> InformationalFields =
    [
        "sourceTeam", "sourceIp", "algorithmId", "algorithmName", "operationName", "payloadMode", "originalFileName",
        "originalExtension", "originalSizeBytes", "contentType", "encryptedSizeBytes", "publicParameters", "signatureAlgorithm",
    ];

    /// <summary>Valor centinela de <c>encryptedSizeBytes</c> omitido: se toma el tamaño real del contenido.</summary>
    private const long UnknownSize = -1;

    /// <summary>
    /// Campos anulables (<c>requestId</c>, <c>parts</c>, <c>keyRef</c>, y en <c>result</c> <c>verification</c> y
    /// <c>resultEnvelope</c>): si otro nodo los omite se tratan como <c>null</c> (ADR 0014). Ninguno entra en la
    /// cadena de firma §8.4. EQ08 siempre los envía.
    /// </summary>
    public static readonly IReadOnlyList<string> NullableFields = ["requestId", "parts", "keyRef", "verification", "resultEnvelope"];

    private static readonly string[] PayloadModes =
    [
        ProtocolConstants.PayloadText, ProtocolConstants.PayloadFile, ProtocolConstants.PayloadImage, ProtocolConstants.PayloadMultipart,
    ];

    public async Task<ValidatedPackage> ValidateAsync(byte[] zip, PackageValidationOptions options, CancellationToken ct)
    {
        var report = await ValidateWithReportAsync(zip, options, ct);
        return report.Error is null ? report.Package! : throw report.Error;
    }

    public async Task<ValidationReport> ValidateWithReportAsync(byte[] zip, PackageValidationOptions options, CancellationToken ct)
    {
        var steps = new List<ValidationStep>();
        var current = 0;
        var description = string.Empty;

        void Begin(int n, string d)
        {
            current = n;
            description = d;
        }

        void Pass() => steps.Add(new ValidationStep(current, description, true));

        try
        {
            Begin(1, "Tamaño ≤ 50 MB");
            if (zip.LongLength > ProtocolConstants.MaxBodyBytes)
            {
                throw new ProtocolException(ErrorCodes.Size, "El paquete supera 50 MB.");
            }

            Pass();

            Begin(2, "Es un zip válido");
            using var archive = ZipSafety.Open(zip);
            var entries = archive.Entries.ToList();
            if (entries.Any(IsEncrypted))
            {
                throw new ProtocolException(ErrorCodes.ZipInvalid, "El zip no debe estar protegido con contraseña.");
            }

            Pass();

            Begin(3, "Exactamente 3 archivos con los nombres de §9.3");
            var names = entries.Select(e => e.FullName).ToHashSet(StringComparer.Ordinal);
            var isPackageSet = names.SetEquals([ProtocolConstants.EntryData, ProtocolConstants.EntryCertificate, ProtocolConstants.EntryManifest]);
            var isResultSet = names.SetEquals([ProtocolConstants.EntryResult, ProtocolConstants.EntryCertificate, ProtocolConstants.EntryManifest]);
            if (entries.Count != ProtocolConstants.ZipEntryCount || entries.Any(e => !ZipSafety.IsFlatName(e.FullName))
                || (!isPackageSet && !isResultSet))
            {
                throw new ProtocolException(ErrorCodes.ZipStructure,
                    "El zip debe tener exactamente datos.enc (o resultado.enc), certificado.pem y manifest.json en la raíz.");
            }

            Pass();

            Begin(4, "Descomprimido ≤ 200 MB y razón ≤ 100:1");
            ZipSafety.CheckBomb(entries, ProtocolConstants.MaxUncompressedBytes);
            Pass();

            Begin(5, "manifest.json válido y completo");
            var manifestBytes = ZipSafety.ReadAll(archive.GetEntry(ProtocolConstants.EntryManifest)!);
            var (manifest, omitted) = ParseManifestDetailed(manifestBytes);
            var dataEntryName = manifest.PacketType == ProtocolConstants.PacketTypeResult
                ? ProtocolConstants.EntryResult
                : ProtocolConstants.EntryData;
            if (!names.Contains(dataEntryName))
            {
                throw new ProtocolException(ErrorCodes.Manifest, "packetType no coincide con los archivos del zip.");
            }

            if (options.ExpectedPacketType is { } expected && manifest.PacketType != expected)
            {
                throw new ProtocolException(ErrorCodes.Manifest, $"Se esperaba un paquete tipo {expected}.");
            }

            Pass();

            Begin(6, "version = 2.0");
            if (!string.Equals(manifest.Version, ProtocolConstants.ProtocolVersion, StringComparison.Ordinal))
            {
                throw new ProtocolException(ErrorCodes.Version, $"Versión de protocolo no soportada: {manifest.Version}.");
            }

            Pass();

            Begin(7, "algorithmId y algorithmCode de la tabla 4.1");
            if (!AlgorithmCatalog.IsConsistent(manifest.AlgorithmId, manifest.AlgorithmCode))
            {
                throw new ProtocolException(ErrorCodes.Algorithm, "algorithmId y algorithmCode no coinciden con la tabla 4.1.");
            }

            Pass();

            Begin(8, "SHA-256 del contenido = encryptedSha256");
            var data = ZipSafety.ReadAll(archive.GetEntry(dataEntryName)!);
            if (manifest.EncryptedSizeBytes == UnknownSize)
            {
                manifest = manifest with { EncryptedSizeBytes = data.LongLength };
            }

            if (data.LongLength != manifest.EncryptedSizeBytes
                || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(data), Convert.FromHexString(manifest.EncryptedSha256)))
            {
                throw new ProtocolException(ErrorCodes.Hash, $"El SHA-256 de {dataEntryName} no coincide con encryptedSha256.");
            }

            IReadOnlyList<byte[]>? parts = null;
            if (manifest.PayloadMode == ProtocolConstants.PayloadMultipart)
            {
                parts = Multipart.ReadAndVerify(data, manifest.Parts);
            }

            Pass();

            Begin(9, "publicParametersSha256 (texto canónico §8.5)");
            var paramsHash = CanonicalParameters.Hash(manifest.PublicParameters);
            if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(paramsHash), Encoding.ASCII.GetBytes(manifest.PublicParametersSha256)))
            {
                throw new ProtocolException(ErrorCodes.ParamsHash, "publicParametersSha256 no coincide con el texto canónico.");
            }

            Pass();

            Begin(10, "Certificado X.509 RSA-2048, CN = sourceNode, vigente");
            var pem = Encoding.ASCII.GetString(ZipSafety.ReadAll(archive.GetEntry(ProtocolConstants.EntryCertificate)!));
            var cert = CertificateTools.LoadAndValidate(pem, manifest.SourceNode, clock.GetUtcNow());
            Pass();

            Begin(11, "Huella del certificado = certificateThumbprintSha256");
            var thumbprint = CertificateTools.Thumbprint(cert);
            if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(thumbprint), Encoding.ASCII.GetBytes(manifest.CertificateThumbprintSha256)))
            {
                throw new ProtocolException(ErrorCodes.CertThumbprint, "La huella de certificado.pem no coincide con el manifiesto.");
            }

            Pass();

            Begin(12, "Firma RSA-PSS-SHA256 sobre la cadena §8.4");
            if (!RsaPss.Verify(cert, SignatureChain.Bytes(manifest), manifest.ManifestSignatureBase64))
            {
                throw new ProtocolException(ErrorCodes.Signature, "La firma del manifiesto no es válida.");
            }

            Pass();

            Begin(13, "timestampUtc dentro de ±10 min");
            if (options.CheckTimestamp)
            {
                CheckTimestamp(manifest.TimestampUtc, clock);
                Pass();
            }
            else
            {
                steps.Add(new ValidationStep(13, description + " (no aplica: se valida la petición, ADR 0005)", true));
            }

            Begin(13, "Huella fijada del remitente (§13.1 nota)");
            var pinned = await trust.GetPinnedThumbprintAsync(manifest.SourceNode, ct);
            if (pinned is not null && !string.Equals(pinned, thumbprint, StringComparison.Ordinal))
            {
                throw new ProtocolException(ErrorCodes.CertUntrusted, $"La huella de {manifest.SourceNode} no coincide con la fijada.");
            }

            Begin(14, "packetId no visto antes");
            if (options.CheckReplay)
            {
                if (!await replay.TryMarkSeenAsync(SeenKindPacket, manifest.PacketId, ct))
                {
                    throw new ProtocolException(ErrorCodes.Duplicate, "El packetId ya fue recibido.");
                }

                Pass();
            }
            else
            {
                steps.Add(new ValidationStep(14, description + " (no aplica: se valida requestId, ADR 0005)", true));
            }

            return new ValidationReport(steps, new ValidatedPackage(zip, manifest, data, pem, cert, pinned is not null, parts, omitted), null);
        }
        catch (ProtocolException ex)
        {
            steps.Add(new ValidationStep(current, description, false, ex.Code, ex.Message));
            return new ValidationReport(steps, null, ex);
        }
    }

    /// <summary>Ventana de ±10 min (§13.1 #13, §13.2 #5).</summary>
    public static void CheckTimestamp(string timestampUtc, TimeProvider clock)
    {
        if (!Identifiers.TryParseTimestamp(timestampUtc, out var ts)
            || (clock.GetUtcNow() - ts).Duration() > ProtocolConstants.TimestampWindow)
        {
            throw new ProtocolException(ErrorCodes.Timestamp, "timestampUtc está fuera de la ventana de ±10 minutos.");
        }
    }

    private static bool IsEncrypted(System.IO.Compression.ZipArchiveEntry entry) => entry.IsEncrypted;

    /// <summary>§13.1 #5: JSON válido, campos obligatorios y formatos de la sección 3.</summary>
    public static Manifest ParseManifest(byte[] json) => ParseManifestDetailed(json).Manifest;

    /// <summary>Como <see cref="ParseManifest"/>, e informa qué campos informativos omitió el remitente.</summary>
    public static (Manifest Manifest, IReadOnlyList<string> Omitted) ParseManifestDetailed(byte[] json)
    {
        Manifest? manifest;
        var omitted = new List<string>();
        try
        {
            if (JsonNode.Parse(json) is not JsonObject root)
            {
                throw new ProtocolException(ErrorCodes.Manifest, "manifest.json debe ser un objeto JSON.");
            }

            var missing = RequiredFields.Where(f => root[f] is null).ToList();
            if (missing.Count > 0)
            {
                throw new ProtocolException(ErrorCodes.Manifest, "Faltan campos obligatorios: " + string.Join(", ", missing) + ".");
            }

            FillInformationalDefaults(root, omitted);
            var isResult = root["packetType"] is JsonValue pt && pt.TryGetValue<string>(out var type) && type == ProtocolConstants.PacketTypeResult;
            omitted.AddRange(NullableFields.Where(f => !root.ContainsKey(f) && (isResult || f is not ("verification" or "resultEnvelope"))));
            if (root["publicParameters"] is not JsonObject pp || pp.Any(p => p.Value is not JsonValue v || v.GetValueKind() != JsonValueKind.String))
            {
                throw new ProtocolException(ErrorCodes.Manifest, "publicParameters debe ser un objeto plano de cadenas.");
            }

            manifest = root.Deserialize<Manifest>(ProtocolJson.Options);
        }
        catch (JsonException ex)
        {
            throw new ProtocolException(ErrorCodes.Manifest, "manifest.json no es JSON válido o tiene tipos incorrectos.", ex);
        }
        catch (InvalidOperationException ex)
        {
            throw new ProtocolException(ErrorCodes.Manifest, "manifest.json tiene tipos incorrectos.", ex);
        }

        return (Validate(manifest), omitted);
    }

    /// <summary>ADR 0016: completa los campos informativos omitidos con valores deducibles.</summary>
    private static void FillInformationalDefaults(JsonObject m, List<string> omitted)
    {
        void Default(string name, Func<JsonNode?> value)
        {
            if (!m.ContainsKey(name) || m[name] is null)
            {
                m[name] = value();
                omitted.Add(name);
            }
        }

        string Text(string name) => m[name] is JsonValue v && v.TryGetValue<string>(out var t) ? t : string.Empty;

        var info = AlgorithmCatalog.ByCode(Text("algorithmCode"));
        Default("sourceTeam", () => Identifiers.IsNodeId(Text("sourceNode"))
            ? int.Parse(Text("sourceNode").AsSpan(2), System.Globalization.CultureInfo.InvariantCulture)
            : 0);
        Default("sourceIp", () => "desconocida");
        Default("algorithmId", () => info?.Id ?? 0);
        Default("algorithmName", () => Text("algorithmCode"));
        Default("operationName", () => info?.OperationName(Text("operation")) ?? Text("operation"));
        Default("payloadMode", () => ProtocolConstants.PayloadFile);
        Default("originalFileName", () => "datos.bin");
        Default("originalExtension", () => Path.GetExtension(Text("originalFileName")));
        Default("originalSizeBytes", () => 0);
        Default("contentType", () => ContentTypes.ForFile(Text("originalFileName"), Text("payloadMode")));
        Default("encryptedSizeBytes", () => UnknownSize);
        Default("publicParameters", () => new JsonObject());
        Default("signatureAlgorithm", () => ProtocolConstants.SignatureAlgorithm);
    }

    private static Manifest Validate(Manifest? manifest)
    {
        if (manifest is null)
        {
            throw new ProtocolException(ErrorCodes.Manifest, "manifest.json está vacío.");
        }

        var problems = new List<string>();
        void Require(bool ok, string field)
        {
            if (!ok)
            {
                problems.Add(field);
            }
        }

        Require(manifest.Version is not null, "version");
        Require(manifest.PacketType is ProtocolConstants.PacketTypePackage or ProtocolConstants.PacketTypeResult, "packetType");
        Require(Identifiers.IsUuidV4(manifest.PacketId), "packetId");
        Require(manifest.RequestId is null || Identifiers.IsUuidV4(manifest.RequestId), "requestId");
        Require(Identifiers.IsNodeId(manifest.SourceNode), "sourceNode");
        Require(Identifiers.IsTeamNumber(manifest.SourceTeam)
            && manifest.SourceNode == ProtocolConstants.NodeIdFor(manifest.SourceTeam), "sourceTeam");
        Require(!string.IsNullOrWhiteSpace(manifest.SourceIp), "sourceIp");
        Require(Identifiers.IsNodeId(manifest.ProducerNode), "producerNode");
        Require(Identifiers.IsTimestamp(manifest.TimestampUtc), "timestampUtc");
        Require(!string.IsNullOrEmpty(manifest.AlgorithmCode), "algorithmCode");
        Require(manifest.AlgorithmName is not null, "algorithmName");
        Require(Identifiers.IsOperation(manifest.Operation), "operation");
        Require(manifest.OperationName is not null, "operationName");
        Require(PayloadModes.Contains(manifest.PayloadMode), "payloadMode");
        Require(manifest.OriginalFileName is not null, "originalFileName");
        Require(manifest.OriginalExtension is not null, "originalExtension");
        Require(manifest.OriginalSizeBytes >= 0, "originalSizeBytes");
        Require(manifest.ContentType is not null, "contentType");
        Require(Identifiers.IsContentHash(manifest.EncryptedSha256), "encryptedSha256");
        Require(manifest.EncryptedSizeBytes >= UnknownSize, "encryptedSizeBytes");
        Require(manifest.PayloadMode != ProtocolConstants.PayloadMultipart
            || (manifest.Parts is { Count: > 0 and <= ProtocolConstants.MultipartMaxEntries }
                && manifest.Parts.All(p => p is not null && ZipSafety.IsFlatName(p.Name) && Identifiers.IsContentHash(p.Sha256) && p.SizeBytes >= 0)), "parts");
        Require(manifest.KeyRef is null || (Identifiers.IsKeyId(manifest.KeyRef.KeyId) && Identifiers.IsNodeId(manifest.KeyRef.OwnerNode)), "keyRef");
        Require(manifest.PublicParameters is not null && manifest.PublicParameters.Values.All(v => v is not null), "publicParameters");
        Require(Identifiers.IsContentHash(manifest.PublicParametersSha256), "publicParametersSha256");
        Require(Identifiers.IsThumbprint(manifest.CertificateThumbprintSha256), "certificateThumbprintSha256");
        Require(manifest.SignatureAlgorithm == ProtocolConstants.SignatureAlgorithm, "signatureAlgorithm");
        Require(!string.IsNullOrEmpty(manifest.ManifestSignatureBase64), "manifestSignatureBase64");
        Require(manifest.ResultEnvelope is null || (Identifiers.IsNodeId(manifest.ResultEnvelope.RecipientNode)
            && Identifiers.IsThumbprint(manifest.ResultEnvelope.RecipientThumbprintSha256)), "resultEnvelope");

        if (problems.Count > 0)
        {
            throw new ProtocolException(ErrorCodes.Manifest, "Campos con formato inválido: " + string.Join(", ", problems) + ".");
        }

        return manifest;
    }
}
