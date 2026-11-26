using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CentroCiber.Crypto.Protocol;

namespace CentroCiber.Crypto.Identity;

/// <summary>
/// Identidad X.509 del nodo (§7): RSA-2048 autofirmado, CN = nodeId, 365 días.
/// La llave privada nunca sale del proceso salvo en <see cref="ExportPfx"/> (protegido con contraseña)
/// o en <see cref="ExportPrivateKeyPem"/>, que solo se usa para los vectores marcados PRUEBA.
/// </summary>
public sealed class NodeIdentity : IDisposable
{
    private NodeIdentity(X509Certificate2 certificate)
    {
        Certificate = certificate;
        NodeId = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
        Thumbprint = CertificateTools.Thumbprint(certificate);
        CertificatePem = certificate.ExportCertificatePem();
    }

    public X509Certificate2 Certificate { get; }

    public string NodeId { get; }

    /// <summary>SHA-256 del DER en hex MAYÚSCULAS.</summary>
    public string Thumbprint { get; }

    public string CertificatePem { get; }

    public RSA PrivateKey => Certificate.GetRSAPrivateKey()
        ?? throw new InvalidOperationException("El certificado de identidad no tiene llave privada.");

    /// <summary>Genera una identidad nueva según §7.</summary>
    public static NodeIdentity Create(int teamNumber, TimeProvider clock)
    {
        if (!Identifiers.IsTeamNumber(teamNumber))
        {
            throw new ArgumentOutOfRangeException(nameof(teamNumber));
        }

        var nodeId = ProtocolConstants.NodeIdFor(teamNumber);
        using var rsa = RSA.Create(ProtocolConstants.IdentityKeySizeBits);
        var request = new CertificateRequest(SubjectFor(teamNumber), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(nodeId.ToLowerInvariant());
        san.AddDnsName("localhost");
        request.CertificateExtensions.Add(san.Build());

        var now = Identifiers.TruncateToSeconds(clock.GetUtcNow());
        // Se adelanta NotBefore 10 min (la misma ventana de §13) para tolerar relojes desfasados.
        var notBefore = now - ProtocolConstants.TimestampWindow;
        var notAfter = now.AddDays(ProtocolConstants.CertificateValidityDays);
        using var generated = request.Create(request.SubjectName, X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1),
            notBefore, notAfter, NewSerialNumber());
        using var withKey = generated.CopyWithPrivateKey(rsa);
        // Se reimporta desde PKCS#12 para obtener una llave utilizable por SslStream en Windows.
        var pfx = withKey.Export(X509ContentType.Pkcs12, (string?)null);
        try
        {
            return new NodeIdentity(X509CertificateLoader.LoadPkcs12(pfx, null, X509KeyStorageFlags.Exportable));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pfx);
        }
    }

    /// <summary>Carga el PFX si existe; si no, genera una identidad y la guarda protegida con la contraseña.</summary>
    public static NodeIdentity LoadOrCreate(string pfxPath, string password, int teamNumber, TimeProvider clock, out bool created)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);
        if (File.Exists(pfxPath))
        {
            created = false;
            var cert = X509CertificateLoader.LoadPkcs12FromFile(pfxPath, password, X509KeyStorageFlags.Exportable);
            return new NodeIdentity(cert);
        }

        var identity = Create(teamNumber, clock);
        identity.SavePfx(pfxPath, password);
        created = true;
        return identity;
    }

    /// <summary>Construye una identidad desde PEM (vectores de prueba y nodos simulados).</summary>
    public static NodeIdentity FromPem(string certificatePem, string privateKeyPem)
    {
        using var cert = X509Certificate2.CreateFromPem(certificatePem, privateKeyPem);
        var pfx = cert.Export(X509ContentType.Pkcs12, (string?)null);
        try
        {
            return new NodeIdentity(X509CertificateLoader.LoadPkcs12(pfx, null, X509KeyStorageFlags.Exportable));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pfx);
        }
    }

    public static X500DistinguishedName SubjectFor(int teamNumber)
    {
        var builder = new X500DistinguishedNameBuilder();
        // El constructor agrega en orden inverso al de presentación: el resultado es
        // "CN=EQnn, OU=Equipo nn, O=Centro de Ciberseguridad, C=MX" (DER: C, O, OU, CN).
        builder.AddCommonName(ProtocolConstants.NodeIdFor(teamNumber));
        builder.AddOrganizationalUnitName(string.Create(System.Globalization.CultureInfo.InvariantCulture, $"Equipo {teamNumber:00}"));
        builder.AddOrganizationName(ProtocolConstants.CertificateOrganization);
        builder.AddCountryOrRegion(ProtocolConstants.CertificateCountry);
        return builder.Build();
    }

    public void SavePfx(string pfxPath, string password)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(pfxPath));
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var bytes = ExportPfx(password);
        try
        {
            File.WriteAllBytes(pfxPath, bytes);
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(pfxPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public byte[] ExportPfx(string password) =>
        Certificate.ExportPkcs12(PbeParameters(), password);

    /// <summary>Solo para vectores de prueba (<c>privada-PRUEBA.pem</c>).</summary>
    public string ExportPrivateKeyPem() => PrivateKey.ExportPkcs8PrivateKeyPem();

    public void Dispose() => Certificate.Dispose();

    private static PbeParameters PbeParameters() =>
        new(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000);

    private static byte[] NewSerialNumber()
    {
        // ≥ 64 bits aleatorios; primer byte positivo y distinto de cero (DER INTEGER).
        var serial = RandomNumberGenerator.GetBytes(9);
        serial[0] = (byte)((serial[0] & 0x7F) | 0x01);
        return serial;
    }
}
