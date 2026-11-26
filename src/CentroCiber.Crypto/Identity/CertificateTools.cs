using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CentroCiber.Crypto.Protocol;

namespace CentroCiber.Crypto.Identity;

/// <summary>Huella y validación de certificados de otros nodos (§7, §13.1 #10–#11).</summary>
public static class CertificateTools
{
    private const string PemBegin = "-----BEGIN CERTIFICATE-----";

    /// <summary>SHA-256 del DER en hex MAYÚSCULAS sin separadores.</summary>
    public static string Thumbprint(X509Certificate2 certificate) => Hex.Upper(SHA256.HashData(certificate.RawData));

    public static string CommonName(X509Certificate2 certificate) =>
        certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);

    /// <summary>
    /// Carga un PEM con exactamente un certificado X.509 RSA-2048, vigente y con CN = <paramref name="expectedNodeId"/>.
    /// Lanza <see cref="ProtocolException"/> con <c>E-CERT</c> si algo no se cumple.
    /// </summary>
    public static X509Certificate2 LoadAndValidate(string pem, string expectedNodeId, DateTimeOffset now)
    {
        X509Certificate2 cert;
        try
        {
            if (CountOccurrences(pem, PemBegin) != 1)
            {
                throw new ProtocolException(ErrorCodes.Cert, "certificado.pem debe contener exactamente un certificado.");
            }

            cert = X509Certificate2.CreateFromPem(pem);
        }
        catch (CryptographicException ex)
        {
            throw new ProtocolException(ErrorCodes.Cert, "certificado.pem no es un certificado X.509 válido.", ex);
        }

        try
        {
            using var rsa = cert.GetRSAPublicKey();
            if (rsa is null || rsa.KeySize != ProtocolConstants.IdentityKeySizeBits)
            {
                throw new ProtocolException(ErrorCodes.Cert, "El certificado debe tener una llave RSA-2048.");
            }

            var cn = CommonName(cert);
            if (!string.Equals(cn, expectedNodeId, StringComparison.Ordinal))
            {
                throw new ProtocolException(ErrorCodes.Cert, $"El CN del certificado ({cn}) no coincide con {expectedNodeId}.");
            }

            var utc = now.UtcDateTime;
            if (utc < cert.NotBefore.ToUniversalTime() || utc > cert.NotAfter.ToUniversalTime())
            {
                throw new ProtocolException(ErrorCodes.Cert, "El certificado no está vigente.");
            }

            return cert;
        }
        catch
        {
            cert.Dispose();
            throw;
        }
    }

    private static int CountOccurrences(string text, string token)
    {
        var count = 0;
        var index = 0;
        while ((index = text.IndexOf(token, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += token.Length;
        }

        return count;
    }
}
