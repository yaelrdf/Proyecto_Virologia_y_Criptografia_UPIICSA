namespace CentroCiber.Crypto.Protocol;

/// <summary>
/// Valores fijos del Estándar de Comunicación v2.0 (Anexo C). Ningún otro archivo
/// debe usar estos literales directamente.
/// </summary>
public static class ProtocolConstants
{
    public const string ProtocolVersion = "2.0";

    // §5.1 Puertos
    public const int HttpPortBase = 5000;
    public const int HttpsPortBase = 5100;
    public const int DiscoveryUdpPort = 5099;
    public const int ScanPortFrom = 5001;
    public const int ScanPortTo = 5020;

    // §6 Descubrimiento
    public const string BeaconType = "CC-BEACON";
    public const int BeaconMaxBytes = 1024;
    public static readonly TimeSpan BeaconInterval = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan OfflineAfter = TimeSpan.FromSeconds(90);
    public static readonly TimeSpan ScanAttemptTimeout = TimeSpan.FromMilliseconds(500);
    public const int ScanMaxParallelism = 64;
    public static readonly TimeSpan ScanMinAutomaticInterval = TimeSpan.FromMinutes(5);
    public const string StatusOnline = "online";
    public const string StatusOffline = "offline";

    // §7 Certificado
    public const int IdentityKeySizeBits = 2048;
    public const int CertificateValidityDays = 365;
    public const string CertificateOrganization = "Centro de Ciberseguridad";
    public const string CertificateCountry = "MX";

    // §8 Primitivas
    public const string SignatureAlgorithm = "RSA-PSS-SHA256";
    public const int PssSaltBytes = 32;
    public const string EnvelopeName = "CC-ENV-1";
    public const int EnvelopeKeyBytes = 32;
    public const int EnvelopeNonceBytes = 12;
    public const int EnvelopeTagBytes = 16;
    public const char SignatureChainSeparator = '|';

    // §9 Paquete
    public const string PacketTypePackage = "package";
    public const string PacketTypeResult = "result";
    public const string EntryData = "datos.enc";
    public const string EntryResult = "resultado.enc";
    public const string EntryCertificate = "certificado.pem";
    public const string EntryManifest = "manifest.json";
    public const string ResultFilePrefix = "RES_";
    public const string ZipExtension = ".zip";
    public const int ZipEntryCount = 3;
    public const int MultipartMaxEntries = 64;
    public const string MultipartPartPrefix = "part-";
    public const string MultipartPartSuffix = ".bin";

    public const string PayloadText = "text";
    public const string PayloadFile = "file";
    public const string PayloadImage = "image";
    public const string PayloadMultipart = "multipart";
    public const string DefaultTextFileName = "mensaje.txt";

    public const string OperationForward = "forward";
    public const string OperationInverse = "inverse";

    // §10 API
    public const long MaxBodyBytes = 50L * 1024 * 1024;
    public const long MaxUncompressedBytes = 200L * 1024 * 1024;
    public const int MaxCompressionRatio = 100;
    public const string HeaderNode = "X-CC-Node";
    public const string HeaderProtocol = "X-CC-Protocol";
    public const string HeaderRequestId = "X-CC-Request-Id";
    public const string ProblemContentType = "application/problem+json";
    public const string PemContentType = "application/x-pem-file";
    public const string ZipContentType = "application/zip";
    public const string ErrorTypeBase = "https://centrociber.local/errors/";

    public const string PartRequest = "request";
    public const string PartRequestSignature = "requestSignature";
    public const string PartRequesterCertificate = "requesterCertificate";
    public const string PartPayload = "payload";
    public const string PartCover = "cover";
    public const string PartPackage = "package";

    public static readonly TimeSpan SyncOperationLimit = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan JobRetention = TimeSpan.FromHours(1);
    public const int JobRetryAfterSeconds = 5;
    public const int MaxConcurrentCryptoRequests = 10;

    // §13 Ventana de tiempo
    public static readonly TimeSpan TimestampWindow = TimeSpan.FromMinutes(10);

    public const string JobQueued = "queued";
    public const string JobRunning = "running";
    public const string JobDone = "done";
    public const string JobFailed = "failed";

    public static int HttpPortFor(int teamNumber) => HttpPortBase + teamNumber;

    public static int HttpsPortFor(int teamNumber) => HttpsPortBase + teamNumber;

    public static string NodeIdFor(int teamNumber) =>
        string.Create(System.Globalization.CultureInfo.InvariantCulture, $"EQ{teamNumber:00}");
}
