using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CentroCiber.Crypto.Identity;
using CentroCiber.Crypto.Protocol;

namespace CentroCiber.Crypto.Tests;

public class IdentityTests
{
    private static readonly TimeProvider Clock = TimeProvider.System;

    [Fact] // Estándar §7
    public void Generated_certificate_follows_section_7()
    {
        using var id = NodeIdentity.Create(8, Clock);
        var cert = id.Certificate;
        cert.Subject.ShouldBe("CN=EQ08, OU=Equipo 08, O=Centro de Ciberseguridad, C=MX");
        cert.Issuer.ShouldBe(cert.Subject);
        cert.SignatureAlgorithm.Value.ShouldBe("1.2.840.113549.1.1.11"); // sha256WithRSAEncryption
        using (var rsa = cert.GetRSAPublicKey()!)
        {
            rsa.KeySize.ShouldBe(2048);
        }

        (cert.NotAfter.ToUniversalTime() - DateTime.UtcNow).TotalDays.ShouldBeInRange(364.9, 365.01);
        cert.GetSerialNumber().Length.ShouldBeGreaterThanOrEqualTo(8);
        var ku = cert.Extensions.OfType<X509KeyUsageExtension>().Single();
        ku.KeyUsages.ShouldBe(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment);
        cert.HasPrivateKey.ShouldBeTrue();
    }

    [Fact] // Estándar §3 y §7: huella = SHA-256 del DER, hex MAYÚSCULAS
    public void Thumbprint_is_uppercase_sha256_of_der()
    {
        using var id = NodeIdentity.Create(8, Clock);
        id.Thumbprint.ShouldBe(Convert.ToHexString(SHA256.HashData(id.Certificate.RawData)));
        Identifiers.IsThumbprint(id.Thumbprint).ShouldBeTrue();
        id.CertificatePem.ShouldStartWith("-----BEGIN CERTIFICATE-----");
    }

    [Fact]
    public void Serial_numbers_are_random()
    {
        using var a = NodeIdentity.Create(8, Clock);
        using var b = NodeIdentity.Create(8, Clock);
        a.Certificate.SerialNumber.ShouldNotBe(b.Certificate.SerialNumber);
    }

    [Fact] // Plan: PFX protegido por CC_PFX_PASSWORD
    public void Pfx_is_created_once_and_reloaded_with_password()
    {
        var dir = Path.Combine(Path.GetTempPath(), "cc-id-" + Guid.NewGuid().ToString("N"));
        var pfx = Path.Combine(dir, "identidad.pfx");
        try
        {
            using var first = NodeIdentity.LoadOrCreate(pfx, "secreto", 8, Clock, out var created1);
            created1.ShouldBeTrue();
            File.Exists(pfx).ShouldBeTrue();
            using var second = NodeIdentity.LoadOrCreate(pfx, "secreto", 8, Clock, out var created2);
            created2.ShouldBeFalse();
            second.Thumbprint.ShouldBe(first.Thumbprint);
            Should.Throw<CryptographicException>(() => NodeIdentity.LoadOrCreate(pfx, "otra", 8, Clock, out _));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact] // Estándar §13.1 #10
    public void Certificate_validation_checks_cn_and_validity()
    {
        using var id = NodeIdentity.Create(8, Clock);
        using var ok = CertificateTools.LoadAndValidate(id.CertificatePem, "EQ08", DateTimeOffset.UtcNow);
        ok.ShouldNotBeNull();
        Should.Throw<ProtocolException>(() => CertificateTools.LoadAndValidate(id.CertificatePem, "EQ01", DateTimeOffset.UtcNow))
            .Code.ShouldBe(ErrorCodes.Cert);
        Should.Throw<ProtocolException>(() => CertificateTools.LoadAndValidate(id.CertificatePem, "EQ08", DateTimeOffset.UtcNow.AddDays(400)))
            .Code.ShouldBe(ErrorCodes.Cert);
        Should.Throw<ProtocolException>(() => CertificateTools.LoadAndValidate("no es pem", "EQ08", DateTimeOffset.UtcNow))
            .Code.ShouldBe(ErrorCodes.Cert);
        Should.Throw<ProtocolException>(() => CertificateTools.LoadAndValidate(id.CertificatePem + id.CertificatePem, "EQ08", DateTimeOffset.UtcNow))
            .Code.ShouldBe(ErrorCodes.Cert);
    }

    [Fact]
    public void Rsa_1024_certificate_is_rejected()
    {
        using var rsa = RSA.Create(1024);
        var req = new CertificateRequest("CN=EQ01", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        Should.Throw<ProtocolException>(() => CertificateTools.LoadAndValidate(cert.ExportCertificatePem(), "EQ01", DateTimeOffset.UtcNow))
            .Code.ShouldBe(ErrorCodes.Cert);
    }

    [Fact]
    public void Identity_round_trips_through_pem()
    {
        using var id = NodeIdentity.Create(8, Clock);
        using var copy = NodeIdentity.FromPem(id.CertificatePem, id.ExportPrivateKeyPem());
        copy.Thumbprint.ShouldBe(id.Thumbprint);
        copy.Certificate.HasPrivateKey.ShouldBeTrue();
    }
}
