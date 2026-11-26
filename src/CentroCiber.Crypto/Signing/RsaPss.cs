using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CentroCiber.Crypto.Signing;

/// <summary>
/// Firma RSA-PSS con SHA-256, MGF1-SHA256 y sal de 32 bytes (§8.2). En .NET la sal PSS
/// es igual a la longitud del hash, es decir, 32 bytes con SHA-256.
/// </summary>
public static class RsaPss
{
    public static byte[] Sign(RSA privateKey, ReadOnlySpan<byte> data) =>
        privateKey.SignData(data.ToArray(), HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

    public static string SignBase64(RSA privateKey, ReadOnlySpan<byte> data) => Convert.ToBase64String(Sign(privateKey, data));

    public static bool Verify(X509Certificate2 certificate, ReadOnlySpan<byte> data, string? signatureBase64)
    {
        if (string.IsNullOrEmpty(signatureBase64))
        {
            return false;
        }

        byte[] signature;
        try
        {
            signature = Convert.FromBase64String(signatureBase64);
        }
        catch (FormatException)
        {
            return false;
        }

        using var rsa = certificate.GetRSAPublicKey();
        if (rsa is null)
        {
            return false;
        }

        try
        {
            return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}
