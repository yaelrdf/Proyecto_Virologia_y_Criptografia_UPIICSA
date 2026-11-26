using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CentroCiber.Crypto.Envelope;
using CentroCiber.Crypto.Identity;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Crypto.Signing;

namespace CentroCiber.Crypto.Tests;

public sealed class SigningAndEnvelopeTests : IDisposable
{
    private readonly NodeIdentity eq08 = NodeIdentity.Create(8, TimeProvider.System);
    private readonly NodeIdentity eq01 = NodeIdentity.Create(1, TimeProvider.System);

    public void Dispose()
    {
        eq08.Dispose();
        eq01.Dispose();
    }

    [Fact] // Estándar §8.2
    public void Pss_signature_verifies_and_detects_tampering()
    {
        var data = Encoding.UTF8.GetBytes("2.0|package|...");
        var sig = RsaPss.SignBase64(eq08.PrivateKey, data);
        RsaPss.Verify(eq08.Certificate, data, sig).ShouldBeTrue();
        RsaPss.Verify(eq08.Certificate, Encoding.UTF8.GetBytes("2.0|package|..!"), sig).ShouldBeFalse();
        RsaPss.Verify(eq01.Certificate, data, sig).ShouldBeFalse();
        RsaPss.Verify(eq08.Certificate, data, "no-base64!").ShouldBeFalse();
    }

    [Fact] // Estándar §8.2: sal de 32 bytes (verificación explícita con la sal exacta)
    public void Pss_salt_is_32_bytes()
    {
        var data = Encoding.UTF8.GetBytes("vector");
        var sig = RsaPss.Sign(eq08.PrivateKey, data);
        using var pub = eq08.Certificate.GetRSAPublicKey()!;
        // Recuperar EM = s^e mod n y comprobar la estructura PSS con sLen = 32.
        var p = pub.ExportParameters(false);
        var n = new System.Numerics.BigInteger(p.Modulus, isUnsigned: true, isBigEndian: true);
        var e = new System.Numerics.BigInteger(p.Exponent, isUnsigned: true, isBigEndian: true);
        var s = new System.Numerics.BigInteger(sig, isUnsigned: true, isBigEndian: true);
        var em = System.Numerics.BigInteger.ModPow(s, e, n).ToByteArray(isUnsigned: true, isBigEndian: true);
        var emLen = 256; // (2048 - 1) / 8 redondeado hacia arriba
        em = new byte[emLen - em.Length].Concat(em).ToArray();
        em[^1].ShouldBe((byte)0xBC);
        var hLen = 32;
        var maskedDb = em[..(emLen - hLen - 1)];
        var h = em[(emLen - hLen - 1)..^1];
        var mask = Mgf1(h, maskedDb.Length);
        var db = maskedDb.Select((b, i) => (byte)(b ^ mask[i])).ToArray();
        db[0] &= 0x7F;
        var sep = Array.IndexOf(db, (byte)0x01);
        var salt = db[(sep + 1)..];
        salt.Length.ShouldBe(ProtocolConstants.PssSaltBytes);
    }

    private static byte[] Mgf1(byte[] seed, int length)
    {
        var output = new List<byte>();
        for (uint counter = 0; output.Count < length; counter++)
        {
            var c = BitConverter.GetBytes(counter);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(c);
            }

            output.AddRange(SHA256.HashData(seed.Concat(c).ToArray()));
        }

        return output.Take(length).ToArray();
    }

    [Fact] // Estándar §8.3
    public void Envelope_round_trip_for_recipient()
    {
        var requestId = Identifiers.NewUuid();
        var sealedEnv = EnvelopeCrypto.Seal("hola"u8, eq08.Certificate, "EQ08", requestId);
        sealedEnv.Envelope.Envelope.ShouldBe("CC-ENV-1");
        sealedEnv.Envelope.RecipientThumbprintSha256.ShouldBe(eq08.Thumbprint);
        Convert.FromBase64String(sealedEnv.Envelope.NonceBase64).Length.ShouldBe(12);
        Convert.FromBase64String(sealedEnv.Envelope.TagBase64).Length.ShouldBe(16);
        EnvelopeCrypto.Open(sealedEnv.Envelope, eq08, requestId).ShouldBe("hola"u8.ToArray());
    }

    [Fact] // Estándar §8.3: E-ENV-RECIPIENT
    public void Envelope_for_other_node_is_rejected()
    {
        var requestId = Identifiers.NewUuid();
        var env = EnvelopeCrypto.Seal("x"u8, eq01.Certificate, "EQ01", requestId).Envelope;
        Should.Throw<ProtocolException>(() => EnvelopeCrypto.Open(env, eq08, requestId)).Code.ShouldBe(ErrorCodes.EnvRecipient);
    }

    [Fact] // Estándar §8.3: AAD = requestId; E-ENV-DECRYPT
    public void Envelope_with_wrong_aad_or_tampered_tag_fails()
    {
        var requestId = Identifiers.NewUuid();
        var env = EnvelopeCrypto.Seal("x"u8, eq08.Certificate, "EQ08", requestId).Envelope;
        Should.Throw<ProtocolException>(() => EnvelopeCrypto.Open(env, eq08, Identifiers.NewUuid())).Code.ShouldBe(ErrorCodes.EnvDecrypt);
        var tag = Convert.FromBase64String(env.TagBase64);
        tag[0] ^= 1;
        Should.Throw<ProtocolException>(() => EnvelopeCrypto.Open(env with { TagBase64 = Convert.ToBase64String(tag) }, eq08, requestId))
            .Code.ShouldBe(ErrorCodes.EnvDecrypt);
    }

    [Fact] // Estándar §8.3: resultados con texto cifrado aparte
    public void Detached_envelope_round_trip()
    {
        var packetId = Identifiers.NewUuid();
        var sealedEnv = EnvelopeCrypto.Seal("original"u8, eq08.Certificate, "EQ08", packetId, includeCiphertext: false);
        sealedEnv.Envelope.CiphertextBase64.ShouldBeNull();
        EnvelopeCrypto.OpenDetached(sealedEnv.Envelope, sealedEnv.Ciphertext, eq08, packetId).ShouldBe("original"u8.ToArray());
    }

    [Fact] // Estándar §8.3: secretos como JSON de cadenas
    public void Secrets_round_trip()
    {
        var requestId = Identifiers.NewUuid();
        var env = EnvelopeCrypto.SealSecrets(new Dictionary<string, string> { ["key"] = "q83vEj==" }, eq08.Certificate, "EQ08", requestId);
        EnvelopeCrypto.OpenSecrets(env, eq08, requestId)["key"].ShouldBe("q83vEj==");
    }
}
