using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace CentroCiber.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Algorithms",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false),
                    Code = table.Column<string>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", nullable: false),
                    Category = table.Column<string>(type: "TEXT", nullable: false),
                    OwnerTeam = table.Column<int>(type: "INTEGER", nullable: true),
                    ForwardName = table.Column<string>(type: "TEXT", nullable: false),
                    InverseName = table.Column<string>(type: "TEXT", nullable: false),
                    KeyKind = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Algorithms", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AuditLog",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    TimestampUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Event = table.Column<string>(type: "TEXT", nullable: false),
                    NodeId = table.Column<string>(type: "TEXT", nullable: true),
                    Code = table.Column<string>(type: "TEXT", nullable: true),
                    Detail = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditLog", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Nodes",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    NodeId = table.Column<string>(type: "TEXT", nullable: false),
                    TeamNumber = table.Column<int>(type: "INTEGER", nullable: false),
                    Ip = table.Column<string>(type: "TEXT", nullable: false),
                    HttpPort = table.Column<int>(type: "INTEGER", nullable: false),
                    HttpsPort = table.Column<int>(type: "INTEGER", nullable: true),
                    PinnedThumbprintSha256 = table.Column<string>(type: "TEXT", nullable: true),
                    ObservedThumbprintSha256 = table.Column<string>(type: "TEXT", nullable: true),
                    CertificatePem = table.Column<string>(type: "TEXT", nullable: true),
                    Algorithms = table.Column<string>(type: "TEXT", nullable: false),
                    Source = table.Column<string>(type: "TEXT", nullable: false),
                    Status = table.Column<string>(type: "TEXT", nullable: false),
                    TrustState = table.Column<string>(type: "TEXT", nullable: false),
                    IsSelf = table.Column<bool>(type: "INTEGER", nullable: false),
                    LastSeenUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    ProfileJson = table.Column<string>(type: "TEXT", nullable: true),
                    LastError = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Nodes", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Packages",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    PacketId = table.Column<string>(type: "TEXT", nullable: false),
                    FileName = table.Column<string>(type: "TEXT", nullable: false),
                    Origin = table.Column<string>(type: "TEXT", nullable: false),
                    PacketType = table.Column<string>(type: "TEXT", nullable: false),
                    AlgorithmCode = table.Column<string>(type: "TEXT", nullable: false),
                    Operation = table.Column<string>(type: "TEXT", nullable: false),
                    SourceNode = table.Column<string>(type: "TEXT", nullable: false),
                    ProducerNode = table.Column<string>(type: "TEXT", nullable: false),
                    RequestId = table.Column<string>(type: "TEXT", nullable: true),
                    EncryptedSha256 = table.Column<string>(type: "TEXT", nullable: false),
                    KeyId = table.Column<string>(type: "TEXT", nullable: true),
                    KeyOwnerNode = table.Column<string>(type: "TEXT", nullable: true),
                    OriginalFileName = table.Column<string>(type: "TEXT", nullable: true),
                    StoragePath = table.Column<string>(type: "TEXT", nullable: true),
                    SizeBytes = table.Column<long>(type: "INTEGER", nullable: false),
                    ManifestJson = table.Column<string>(type: "TEXT", nullable: false),
                    VerificationValid = table.Column<bool>(type: "INTEGER", nullable: true),
                    VerificationDetail = table.Column<string>(type: "TEXT", nullable: true),
                    IsSample = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Packages", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "RemoteOperations",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    RequestId = table.Column<string>(type: "TEXT", nullable: false),
                    Direction = table.Column<string>(type: "TEXT", nullable: false),
                    PeerNode = table.Column<string>(type: "TEXT", nullable: false),
                    AlgorithmCode = table.Column<string>(type: "TEXT", nullable: false),
                    Operation = table.Column<string>(type: "TEXT", nullable: false),
                    JobId = table.Column<string>(type: "TEXT", nullable: true),
                    State = table.Column<string>(type: "TEXT", nullable: false),
                    ErrorCode = table.Column<string>(type: "TEXT", nullable: true),
                    ErrorDetail = table.Column<string>(type: "TEXT", nullable: true),
                    ResultPackageId = table.Column<int>(type: "INTEGER", nullable: true),
                    CreatedUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RemoteOperations", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Requests",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    PacketId = table.Column<string>(type: "TEXT", nullable: false),
                    SourceNode = table.Column<string>(type: "TEXT", nullable: false),
                    SourceIp = table.Column<string>(type: "TEXT", nullable: false),
                    FileName = table.Column<string>(type: "TEXT", nullable: false),
                    AlgorithmCode = table.Column<string>(type: "TEXT", nullable: false),
                    OperationName = table.Column<string>(type: "TEXT", nullable: false),
                    ValidationResult = table.Column<string>(type: "TEXT", nullable: false),
                    Status = table.Column<string>(type: "TEXT", nullable: false),
                    ErrorCode = table.Column<string>(type: "TEXT", nullable: true),
                    StoragePath = table.Column<string>(type: "TEXT", nullable: true),
                    ManifestJson = table.Column<string>(type: "TEXT", nullable: true),
                    PackageId = table.Column<int>(type: "INTEGER", nullable: true),
                    IsSample = table.Column<bool>(type: "INTEGER", nullable: false),
                    ReceivedUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    DecidedUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Requests", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SeenIds",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", nullable: false),
                    Kind = table.Column<string>(type: "TEXT", nullable: false),
                    SeenUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SeenIds", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Settings",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false),
                    EnabledVariants = table.Column<string>(type: "TEXT", nullable: false),
                    HttpsEnabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    AcceptingPackages = table.Column<bool>(type: "INTEGER", nullable: false),
                    MaxPayloadBytes = table.Column<long>(type: "INTEGER", nullable: false),
                    PfxFileName = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Settings", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Teams",
                columns: table => new
                {
                    TeamNumber = table.Column<int>(type: "INTEGER", nullable: false),
                    NodeId = table.Column<string>(type: "TEXT", nullable: false),
                    HttpPort = table.Column<int>(type: "INTEGER", nullable: false),
                    HttpsPort = table.Column<int>(type: "INTEGER", nullable: false),
                    AlgorithmCodes = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Teams", x => x.TeamNumber);
                });

            migrationBuilder.InsertData(
                table: "Algorithms",
                columns: new[] { "Id", "Category", "Code", "ForwardName", "InverseName", "KeyKind", "Name", "OwnerTeam" },
                values: new object[,]
                {
                    { 1, "Simétrico por bloques", "AESGCM", "cifrar", "descifrar", "Secret", "AES-256-GCM / AES-128-GCM", 1 },
                    { 2, "Simétrico legado", "DES", "cifrar", "descifrar", "Secret", "DES 56-bit", 1 },
                    { 3, "Simétrico legado", "TRIPLEDES", "cifrar", "descifrar", "Secret", "Triple DES / 3DES", 2 },
                    { 4, "Simétrico de flujo (AEAD)", "CHACHA20", "cifrar", "descifrar", "Secret", "ChaCha20-Poly1305", 2 },
                    { 5, "Asimétrico", "RSA", "cifrar", "descifrar", "KeyId", "RSA-OAEP / RSA-PSS", 3 },
                    { 6, "Asimétrico (curva elíptica)", "ECC", "cifrar", "descifrar", "KeyId", "ECDH / ECIES / ECDSA", 3 },
                    { 7, "Acuerdo de claves", "DIFFIEHELLMAN", "cifrar", "descifrar", "KeyId", "Diffie-Hellman", 4 },
                    { 8, "Clásico", "CAESAR", "cifrar", "descifrar", "Secret", "Cifrado César", 4 },
                    { 9, "Clásico polialfabético", "VIGENERE", "cifrar", "descifrar", "Secret", "Cifrado Vigenère", 5 },
                    { 10, "Bajo nivel", "XORASM", "cifrar", "descifrar", "Secret", "XOR en registro (WREG/ROL/ROR)", 5 },
                    { 11, "Esteganografía", "LSBSTEGO", "ocultar", "extraer", "OptionalSecret", "Esteganografía LSB en PNG/BMP", 6 },
                    { 12, "Teoría de números", "EUCLIDESAFFINE", "cifrar", "descifrar", "Secret", "Euclides extendido / Afín", 6 },
                    { 13, "Primalidad", "MILLERRABIN", "cifrar", "descifrar", "KeyId", "Miller–Rabin + cifrado modular", 7 },
                    { 14, "Transposición", "FISHERYATES", "permutar", "restaurar", "Secret", "Permutación Fisher–Yates", 7 },
                    { 15, "Integridad", "HASHSHA", "calcular hash", "verificar", "None", "SHA-256 / SHA-512 / SHA-3", 8 },
                    { 16, "Autenticación", "HMACSHA256", "calcular MAC", "verificar", "Secret", "HMAC-SHA256 / HMAC-SHA512", 8 },
                    { 17, "Autenticidad", "DIGITALSIG", "firmar", "verificar", "KeyId", "Firma digital RSA-PSS / ECDSA", null },
                    { 18, "Poscuántica", "QUANTUMPQC", "cifrar", "descifrar", "KeyId", "QKD BB84 + PQC (ML-KEM / LWE)", null },
                    { 19, "Señales", "DFTSPECTRAL", "transformar", "invertir", "OptionalSecret", "Transformada discreta de Fourier", null },
                    { 20, "Umbral", "LAGRANGESHAMIR", "dividir", "reconstruir", "None", "Shamir en GF(256)", null },
                    { 21, "Flujo electromecánico", "LORENZSZ40", "cifrar", "descifrar", "Secret", "Lorenz SZ40/42", null }
                });

            migrationBuilder.InsertData(
                table: "Nodes",
                columns: new[] { "Id", "Algorithms", "CertificatePem", "HttpPort", "HttpsPort", "Ip", "IsSelf", "LastError", "LastSeenUtc", "NodeId", "ObservedThumbprintSha256", "PinnedThumbprintSha256", "ProfileJson", "Source", "Status", "TeamNumber", "TrustState" },
                values: new object[] { 1, "HASHSHA,HMACSHA256", null, 5008, 5108, "127.0.0.1", true, null, new DateTime(2026, 11, 25, 15, 47, 0, 0, DateTimeKind.Utc), "EQ08", null, null, null, "manual", "online", 8, "Propio" });

            migrationBuilder.InsertData(
                table: "Packages",
                columns: new[] { "Id", "AlgorithmCode", "CreatedUtc", "EncryptedSha256", "FileName", "IsSample", "KeyId", "KeyOwnerNode", "ManifestJson", "Operation", "Origin", "OriginalFileName", "PacketId", "PacketType", "ProducerNode", "RequestId", "SizeBytes", "SourceNode", "StoragePath", "VerificationDetail", "VerificationValid" },
                values: new object[,]
                {
                    { 1, "HASHSHA", new DateTime(2026, 11, 25, 15, 48, 0, 0, DateTimeKind.Utc), "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "EQ08_HASHSHA_20261125_154700_9F86D081.zip", true, null, null, "{\"ejemplo\":true}", "forward", "Generado", "documento.pdf", "5f0d3a52-8c1e-4b7a-9e21-0f6c1d2a3b41", "package", "EQ08", null, 0L, "EQ08", null, null, null },
                    { 2, "HMACSHA256", new DateTime(2026, 11, 25, 15, 49, 0, 0, DateTimeKind.Utc), "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae", "EQ08_HMACSHA256_20261125_155000_2C26B46B.zip", true, null, null, "{\"ejemplo\":true}", "forward", "Generado", "mensaje.txt", "6a1e4b63-9d2f-4c8b-8f32-1a7d2e3b4c52", "package", "EQ08", null, 0L, "EQ08", null, null, null },
                    { 3, "AESGCM", new DateTime(2026, 11, 25, 15, 50, 0, 0, DateTimeKind.Utc), "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce", "EQ01_AESGCM_20261125_160000_4E07408B.zip", true, null, null, "{\"ejemplo\":true}", "forward", "Recibido", "foto.png", "7b2f5c74-ae30-4d9c-9a43-2b8e3f4c5d63", "package", "EQ01", null, 0L, "EQ01", null, null, null },
                    { 4, "HASHSHA", new DateTime(2026, 11, 25, 15, 51, 0, 0, DateTimeKind.Utc), "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c", "RES_EQ08_HASHSHA_20261125_161000_B5BB9D80.zip", true, null, null, "{\"ejemplo\":true}", "inverse", "Resultado", "documento.pdf", "8c3a6d85-bf41-4eab-8b54-3c9f4a5d6e74", "result", "EQ08", null, 0L, "EQ08", null, "Hash coincide (registro de ejemplo)", true }
                });

            migrationBuilder.InsertData(
                table: "Requests",
                columns: new[] { "Id", "AlgorithmCode", "DecidedUtc", "ErrorCode", "FileName", "IsSample", "ManifestJson", "OperationName", "PackageId", "PacketId", "ReceivedUtc", "SourceIp", "SourceNode", "Status", "StoragePath", "ValidationResult" },
                values: new object[,]
                {
                    { 1, "AESGCM", null, null, "EQ01_AESGCM_20261125_162000_1B4F0E98.zip", true, null, "cifrar", null, "9d4b7e96-c052-4fbc-9c65-4d0a5b6e7f85", new DateTime(2026, 11, 25, 16, 18, 0, 0, DateTimeKind.Utc), "192.168.1.21:5001", "EQ01", "Pendiente", null, "Firma OK" },
                    { 2, "VIGENERE", new DateTime(2026, 11, 25, 16, 29, 0, 0, DateTimeKind.Utc), null, "EQ05_VIGENERE_20261125_162500_60303AE2.zip", true, null, "cifrar", null, "ae5c8fa7-d163-4acd-8d76-5e1b6c7f8096", new DateTime(2026, 11, 25, 16, 19, 0, 0, DateTimeKind.Utc), "192.168.1.25:5005", "EQ05", "Aceptada", null, "Remitente no confirmado" },
                    { 3, "RSA", new DateTime(2026, 11, 25, 16, 30, 0, 0, DateTimeKind.Utc), "E-SIGNATURE", "EQ03_RSA_20261125_163000_FD61A03A.zip", true, null, "cifrar", null, "bf6d9ab8-e274-4bde-be87-6f2c7d8091a7", new DateTime(2026, 11, 25, 16, 20, 0, 0, DateTimeKind.Utc), "192.168.1.23:5003", "EQ03", "Rechazada", null, "Inválida" }
                });

            migrationBuilder.InsertData(
                table: "Settings",
                columns: new[] { "Id", "AcceptingPackages", "EnabledVariants", "HttpsEnabled", "MaxPayloadBytes", "PfxFileName" },
                values: new object[] { 1, true, "SHA-256,SHA-512,HMAC-SHA256", true, 52428800L, "identidad.pfx" });

            migrationBuilder.InsertData(
                table: "Teams",
                columns: new[] { "TeamNumber", "AlgorithmCodes", "HttpPort", "HttpsPort", "NodeId" },
                values: new object[,]
                {
                    { 1, "AESGCM,DES", 5001, 5101, "EQ01" },
                    { 2, "TRIPLEDES,CHACHA20", 5002, 5102, "EQ02" },
                    { 3, "RSA,ECC", 5003, 5103, "EQ03" },
                    { 4, "DIFFIEHELLMAN,CAESAR", 5004, 5104, "EQ04" },
                    { 5, "VIGENERE,XORASM", 5005, 5105, "EQ05" },
                    { 6, "LSBSTEGO,EUCLIDESAFFINE", 5006, 5106, "EQ06" },
                    { 7, "MILLERRABIN,FISHERYATES", 5007, 5107, "EQ07" },
                    { 8, "HASHSHA,HMACSHA256", 5008, 5108, "EQ08" }
                });

            migrationBuilder.CreateIndex(
                name: "IX_Algorithms_Code",
                table: "Algorithms",
                column: "Code",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AuditLog_TimestampUtc",
                table: "AuditLog",
                column: "TimestampUtc");

            migrationBuilder.CreateIndex(
                name: "IX_Nodes_NodeId",
                table: "Nodes",
                column: "NodeId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Packages_Origin",
                table: "Packages",
                column: "Origin");

            migrationBuilder.CreateIndex(
                name: "IX_Packages_PacketId",
                table: "Packages",
                column: "PacketId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RemoteOperations_JobId",
                table: "RemoteOperations",
                column: "JobId");

            migrationBuilder.CreateIndex(
                name: "IX_RemoteOperations_RequestId",
                table: "RemoteOperations",
                column: "RequestId");

            migrationBuilder.CreateIndex(
                name: "IX_Requests_Status",
                table: "Requests",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_Teams_NodeId",
                table: "Teams",
                column: "NodeId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Algorithms");

            migrationBuilder.DropTable(
                name: "AuditLog");

            migrationBuilder.DropTable(
                name: "Nodes");

            migrationBuilder.DropTable(
                name: "Packages");

            migrationBuilder.DropTable(
                name: "RemoteOperations");

            migrationBuilder.DropTable(
                name: "Requests");

            migrationBuilder.DropTable(
                name: "SeenIds");

            migrationBuilder.DropTable(
                name: "Settings");

            migrationBuilder.DropTable(
                name: "Teams");
        }
    }
}
