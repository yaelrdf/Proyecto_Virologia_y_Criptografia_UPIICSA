using CentroCiber.Crypto.Protocol;
using CentroCiber.Infrastructure.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace CentroCiber.Infrastructure.Data;

/// <summary>
/// Semilla de la base de datos: 21 algoritmos + 8 equipos + 1 nodo propio + 4 paquetes
/// + 3 solicitudes + 1 ajustes = 38 registros. Los paquetes y solicitudes son de ejemplo
/// (<c>IsSample</c>) y no tienen zip en disco.
/// </summary>
public static class SeedData
{
    public const int ExpectedRecordCount = 38;

    private static readonly DateTime SeedTime = new(2026, 11, 25, 15, 47, 0, DateTimeKind.Utc);

    public static void Apply(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<AlgorithmEntity>().HasData(AlgorithmCatalog.All.Select(a => new AlgorithmEntity
        {
            Id = a.Id,
            Code = a.Code,
            Name = a.Name,
            Category = a.Category,
            OwnerTeam = a.OwnerTeam,
            ForwardName = a.ForwardName,
            InverseName = a.InverseName,
            KeyKind = a.KeyKind.ToString(),
        }));

        modelBuilder.Entity<TeamEntity>().HasData(AlgorithmCatalog.AssignedTeams.Select(t => new TeamEntity
        {
            TeamNumber = t,
            NodeId = ProtocolConstants.NodeIdFor(t),
            HttpPort = ProtocolConstants.HttpPortFor(t),
            HttpsPort = ProtocolConstants.HttpsPortFor(t),
            AlgorithmCodes = string.Join(',', AlgorithmCatalog.OwnedBy(t).Select(a => a.Code)),
        }));

        modelBuilder.Entity<NodeEntity>().HasData(new NodeEntity
        {
            Id = 1,
            NodeId = "EQ08",
            TeamNumber = 8,
            Ip = "127.0.0.1",
            HttpPort = 5008,
            HttpsPort = 5108,
            Algorithms = "HASHSHA,HMACSHA256",
            Source = NodeSources.Manual,
            Status = ProtocolConstants.StatusOnline,
            TrustState = TrustStates.Self,
            IsSelf = true,
            LastSeenUtc = SeedTime,
        });

        modelBuilder.Entity<PackageEntity>().HasData(
            Sample(1, "5f0d3a52-8c1e-4b7a-9e21-0f6c1d2a3b41", "EQ08_HASHSHA_20261125_154700_9F86D081.zip", PackageOrigins.Generated, "package", "HASHSHA", "forward", "EQ08", "EQ08", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "documento.pdf", null),
            Sample(2, "6a1e4b63-9d2f-4c8b-8f32-1a7d2e3b4c52", "EQ08_HMACSHA256_20261125_155000_2C26B46B.zip", PackageOrigins.Generated, "package", "HMACSHA256", "forward", "EQ08", "EQ08", "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae", "mensaje.txt", null),
            Sample(3, "7b2f5c74-ae30-4d9c-9a43-2b8e3f4c5d63", "EQ01_AESGCM_20261125_160000_4E07408B.zip", PackageOrigins.Received, "package", "AESGCM", "forward", "EQ01", "EQ01", "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce", "foto.png", null),
            Sample(4, "8c3a6d85-bf41-4eab-8b54-3c9f4a5d6e74", "RES_EQ08_HASHSHA_20261125_161000_B5BB9D80.zip", PackageOrigins.Result, "result", "HASHSHA", "inverse", "EQ08", "EQ08", "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c", "documento.pdf", true));

        modelBuilder.Entity<InboxRequestEntity>().HasData(
            Inbox(1, "9d4b7e96-c052-4fbc-9c65-4d0a5b6e7f85", "EQ01", "192.168.1.21:5001", "EQ01_AESGCM_20261125_162000_1B4F0E98.zip", "AESGCM", "cifrar", ValidationLabels.SignatureOk, RequestStates.Pending),
            Inbox(2, "ae5c8fa7-d163-4acd-8d76-5e1b6c7f8096", "EQ05", "192.168.1.25:5005", "EQ05_VIGENERE_20261125_162500_60303AE2.zip", "VIGENERE", "cifrar", ValidationLabels.Unconfirmed, RequestStates.Accepted),
            Inbox(3, "bf6d9ab8-e274-4bde-be87-6f2c7d8091a7", "EQ03", "192.168.1.23:5003", "EQ03_RSA_20261125_163000_FD61A03A.zip", "RSA", "cifrar", ValidationLabels.Invalid, RequestStates.Rejected));

        modelBuilder.Entity<SettingsEntity>().HasData(new SettingsEntity
        {
            Id = 1,
            EnabledVariants = "SHA-256,SHA-512,HMAC-SHA256",
            HttpsEnabled = true,
            AcceptingPackages = true,
            AutoAcceptInbox = false,
            MaxPayloadBytes = ProtocolConstants.MaxBodyBytes,
            PfxFileName = "identidad.pfx",
        });
    }

    private static PackageEntity Sample(int id, string packetId, string fileName, string origin, string type,
        string code, string operation, string source, string producer, string sha, string original, bool? valid) => new()
        {
            Id = id,
            PacketId = packetId,
            FileName = fileName,
            Origin = origin,
            PacketType = type,
            AlgorithmCode = code,
            Operation = operation,
            SourceNode = source,
            ProducerNode = producer,
            EncryptedSha256 = sha,
            OriginalFileName = original,
            ManifestJson = "{\"ejemplo\":true}",
            VerificationValid = valid,
            VerificationDetail = valid is null ? null : "Hash coincide (registro de ejemplo)",
            IsSample = true,
            CreatedUtc = SeedTime.AddMinutes(id),
        };

    private static InboxRequestEntity Inbox(int id, string packetId, string source, string ip, string file,
        string code, string opName, string validation, string status) => new()
        {
            Id = id,
            PacketId = packetId,
            SourceNode = source,
            SourceIp = ip,
            FileName = file,
            AlgorithmCode = code,
            OperationName = opName,
            ValidationResult = validation,
            Status = status,
            ErrorCode = validation == ValidationLabels.Invalid ? ErrorCodes.Signature : null,
            IsSample = true,
            ReceivedUtc = SeedTime.AddMinutes(30 + id),
            DecidedUtc = status == RequestStates.Pending ? null : SeedTime.AddMinutes(40 + id),
        };
}
