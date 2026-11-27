using System.Collections.Frozen;

namespace CentroCiber.Crypto.Protocol;

/// <summary>Tipo de llave de un algoritmo (tabla 4.1).</summary>
public enum KeyKind
{
    None,
    Secret,
    OptionalSecret,
    KeyId,
}

/// <summary>Fila del diccionario oficial 4.1 más los parámetros mínimos de 4.2.</summary>
public sealed record AlgorithmInfo(
    int Id,
    string Code,
    string Name,
    string Category,
    int? OwnerTeam,
    string ForwardName,
    string InverseName,
    KeyKind KeyKind,
    IReadOnlyList<string> SecretParameters,
    IReadOnlyList<string> PublicParameters)
{
    public string? OwnerNodeId => OwnerTeam is { } t ? ProtocolConstants.NodeIdFor(t) : null;

    public bool IsReserved => OwnerTeam is null;

    public string OperationName(string operation) =>
        operation == ProtocolConstants.OperationForward ? ForwardName : InverseName;
}

/// <summary>Diccionario de equipos y algoritmos (§4.1 y §4.2 del estándar v2.0).</summary>
public static class AlgorithmCatalog
{
    public const string HashSha = "HASHSHA";
    public const string HmacSha256 = "HMACSHA256";
    public const string AesGcm = "AESGCM";
    public const string ChaCha20 = "CHACHA20";

    /// <summary>
    /// Algoritmos cuyo AAD es el <c>packetId</c> (§4.2). Al reenviarlos se conserva el <c>packetId</c>
    /// para que el dueño pueda descifrarlos (ADR 0015).
    /// </summary>
    public static IReadOnlySet<string> PacketIdAadAlgorithms { get; } = new HashSet<string>(StringComparer.Ordinal) { AesGcm, ChaCha20 };

    private static readonly AlgorithmInfo[] Rows =
    [
        new(1, "AESGCM", "AES-256-GCM / AES-128-GCM", "Simétrico por bloques", 1, "cifrar", "descifrar", KeyKind.Secret, ["key"], ["keySizeBits", "nonceBase64", "tagBase64"]),
        new(2, "DES", "DES 56-bit", "Simétrico legado", 1, "cifrar", "descifrar", KeyKind.Secret, ["key"], ["mode", "padding", "ivBase64"]),
        new(3, "TRIPLEDES", "Triple DES / 3DES", "Simétrico legado", 2, "cifrar", "descifrar", KeyKind.Secret, ["key"], ["mode", "padding", "ivBase64"]),
        new(4, "CHACHA20", "ChaCha20-Poly1305", "Simétrico de flujo (AEAD)", 2, "cifrar", "descifrar", KeyKind.Secret, ["key"], ["nonceBase64", "tagBase64"]),
        new(5, "RSA", "RSA-OAEP / RSA-PSS", "Asimétrico", 3, "cifrar", "descifrar", KeyKind.KeyId, [], ["keyId", "scheme", "wrappedKeyBase64", "nonceBase64", "tagBase64"]),
        new(6, "ECC", "ECDH / ECIES / ECDSA", "Asimétrico (curva elíptica)", 3, "cifrar", "descifrar", KeyKind.KeyId, [], ["keyId", "curve", "scheme", "ephemeralPublicKeyBase64", "nonceBase64", "tagBase64"]),
        new(7, "DIFFIEHELLMAN", "Diffie-Hellman", "Acuerdo de claves", 4, "cifrar", "descifrar", KeyKind.KeyId, [], ["keyId", "pBase64", "g", "publicValueBase64", "kdf", "nonceBase64", "tagBase64"]),
        new(8, "CAESAR", "Cifrado César", "Clásico", 4, "cifrar", "descifrar", KeyKind.Secret, ["shift"], ["alphabet"]),
        new(9, "VIGENERE", "Cifrado Vigenère", "Clásico polialfabético", 5, "cifrar", "descifrar", KeyKind.Secret, ["key"], ["alphabet"]),
        new(10, "XORASM", "XOR en registro (WREG/ROL/ROR)", "Bajo nivel", 5, "cifrar", "descifrar", KeyKind.Secret, ["key"], ["rotation", "rotationBits"]),
        new(11, "LSBSTEGO", "Esteganografía LSB en PNG/BMP", "Esteganografía", 6, "ocultar", "extraer", KeyKind.OptionalSecret, ["password"], ["imageFormat", "bitsPerChannel", "channels", "payloadLengthBytes"]),
        new(12, "EUCLIDESAFFINE", "Euclides extendido / Afín", "Teoría de números", 6, "cifrar", "descifrar", KeyKind.Secret, ["a", "b"], ["modulus"]),
        new(13, "MILLERRABIN", "Miller–Rabin + cifrado modular", "Primalidad", 7, "cifrar", "descifrar", KeyKind.KeyId, [], ["keyId", "modulusBase64", "exponent", "rounds"]),
        new(14, "FISHERYATES", "Permutación Fisher–Yates", "Transposición", 7, "permutar", "restaurar", KeyKind.Secret, ["seed"], ["blockSize", "prng"]),
        new(15, "HASHSHA", "SHA-256 / SHA-512 / SHA-3", "Integridad", 8, "calcular hash", "verificar", KeyKind.None, [], ["hashAlgorithm", "digestHex"]),
        new(16, "HMACSHA256", "HMAC-SHA256 / HMAC-SHA512", "Autenticación", 8, "calcular MAC", "verificar", KeyKind.Secret, ["key"], ["macAlgorithm", "macHex"]),
        new(17, "DIGITALSIG", "Firma digital RSA-PSS / ECDSA", "Autenticidad", null, "firmar", "verificar", KeyKind.KeyId, [], ["keyId", "signatureScheme", "signatureBase64"]),
        new(18, "QUANTUMPQC", "QKD BB84 + PQC (ML-KEM / LWE)", "Poscuántica", null, "cifrar", "descifrar", KeyKind.KeyId, [], ["keyId", "kem", "kemCiphertextBase64", "nonceBase64", "tagBase64"]),
        new(19, "DFTSPECTRAL", "Transformada discreta de Fourier", "Señales", null, "transformar", "invertir", KeyKind.OptionalSecret, ["key"], ["n", "scale", "sampleFormat"]),
        new(20, "LAGRANGESHAMIR", "Shamir en GF(256)", "Umbral", null, "dividir", "reconstruir", KeyKind.None, [], ["threshold", "shares", "field"]),
        new(21, "LORENZSZ40", "Lorenz SZ40/42", "Flujo electromecánico", null, "cifrar", "descifrar", KeyKind.Secret, ["wheelStarts"], ["wheelPatternId"]),
    ];

    public static IReadOnlyList<AlgorithmInfo> All => Rows;

    private static readonly FrozenDictionary<string, AlgorithmInfo> ByCodeMap =
        Rows.ToFrozenDictionary(r => r.Code, StringComparer.Ordinal);

    private static readonly FrozenDictionary<int, AlgorithmInfo> ByIdMap = Rows.ToFrozenDictionary(r => r.Id);

    public static AlgorithmInfo? ByCode(string? code) =>
        code is not null && ByCodeMap.TryGetValue(code, out var info) ? info : null;

    public static AlgorithmInfo? ById(int id) => ByIdMap.TryGetValue(id, out var info) ? info : null;

    /// <summary>Equipos con asignación en la tabla 4.1 (1–8).</summary>
    public static IReadOnlyList<int> AssignedTeams { get; } =
        Rows.Where(r => r.OwnerTeam is not null).Select(r => r.OwnerTeam!.Value).Distinct().Order().ToArray();

    public static IReadOnlyList<AlgorithmInfo> OwnedBy(int teamNumber) =>
        Rows.Where(r => r.OwnerTeam == teamNumber).ToArray();

    /// <summary>§13.1 #7: algorithmId y algorithmCode coinciden con la tabla 4.1.</summary>
    public static bool IsConsistent(int algorithmId, string? algorithmCode) =>
        ById(algorithmId) is { } info && string.Equals(info.Code, algorithmCode, StringComparison.Ordinal);
}
