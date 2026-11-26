using System.Text;
using CentroCiber.Crypto.Algorithms;
using CentroCiber.Crypto.Protocol;

namespace CentroCiber.Crypto.Tests;

public class AlgorithmTests
{
    private static readonly Dictionary<string, string> None = [];

    [Theory] // NIST FIPS 180-4 (ejemplos SHA-256 y SHA-512)
    [InlineData("SHA-256", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")]
    [InlineData("SHA-256", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]
    [InlineData("SHA-256", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")]
    [InlineData("SHA-512", "abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")]
    [InlineData("SHA-512", "", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")]
    [InlineData("SHA-512", "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909")]
    public void Sha2_nist_vectors(string variant, string message, string expected) =>
        Hex.Lower(HashShaAlgorithm.Compute(variant, Encoding.ASCII.GetBytes(message))).ShouldBe(expected);

    [Fact] // NIST: un millón de 'a'
    public void Sha256_million_a() =>
        Hex.Lower(HashShaAlgorithm.Compute("SHA-256", Enumerable.Repeat((byte)'a', 1_000_000).ToArray()))
            .ShouldBe("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

    [Fact] // Estándar §4.2 y §4.3 HASHSHA
    public void HashSha_forward_and_inverse()
    {
        var alg = new HashShaAlgorithm();
        var data = "abc"u8.ToArray();
        var fwd = alg.Forward(new ForwardInput(data, new Dictionary<string, string> { ["hashAlgorithm"] = "SHA-512" }, None));
        fwd.Data.ShouldBe(data); // datos.enc = original
        fwd.PublicParameters["hashAlgorithm"].ShouldBe("SHA-512");
        fwd.PublicParameters["digestHex"].Length.ShouldBe(128);
        fwd.AlgorithmName.ShouldBe("SHA-512");

        var ok = alg.Inverse(new InverseInput(data, fwd.PublicParameters, None, None));
        ok.Valid.ShouldBe(true);
        ok.Original.ShouldBe(data);

        var bad = alg.Inverse(new InverseInput("abd"u8.ToArray(), fwd.PublicParameters, None, None));
        bad.Valid.ShouldBe(false); // veredicto, no error (plan §2.1)
    }

    [Fact] // Estándar §13.2 #8: E-PARAMS
    public void HashSha_rejects_unsupported_variant_and_secrets()
    {
        var alg = new HashShaAlgorithm();
        Should.Throw<ProtocolException>(() => alg.Forward(new ForwardInput([], new Dictionary<string, string> { ["hashAlgorithm"] = "SHA3-256" }, None)))
            .Code.ShouldBe(ErrorCodes.Params);
        Should.Throw<ProtocolException>(() => alg.Forward(new ForwardInput([], None, new Dictionary<string, string> { ["key"] = "x" })))
            .Code.ShouldBe(ErrorCodes.Params);
        Should.Throw<ProtocolException>(() => alg.Forward(new ForwardInput([], new Dictionary<string, string> { ["otro"] = "x" }, None)))
            .Code.ShouldBe(ErrorCodes.Params);
    }

    public static TheoryData<string, string, string> Rfc4231 => new()
    {
        { "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4869205468657265", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" },
        { "4a656665", "7768617420646f2079612077616e7420666f72206e6f7468696e673f", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" },
        { new string('a', 40), new string('d', 100), "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe" },
        { "0102030405060708090a0b0c0d0e0f10111213141516171819", string.Concat(Enumerable.Repeat("cd", 50)), "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b" },
        { "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", "546573742057697468205472756e636174696f6e", "a3b6167473100ee06e0c796c2955552b" },
        { new string('a', 262), "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374", "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54" },
        { new string('a', 262), Convert.ToHexString(Encoding.ASCII.GetBytes("This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.")), "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2" },
    };

    [Theory] // RFC 4231 casos 1–7 (el caso 5 se compara truncado a 128 bits)
    [MemberData(nameof(Rfc4231))]
    public void Hmac_sha256_rfc4231(string keyHex, string dataHex, string expected) =>
        Hex.Lower(HmacSha256Algorithm.Compute(Convert.FromHexString(keyHex), Convert.FromHexString(dataHex)))
            .ShouldStartWith(expected);

    [Fact] // Estándar §4.2 y §4.3 HMACSHA256
    public void Hmac_forward_and_inverse_with_32_byte_key()
    {
        var alg = new HmacSha256Algorithm();
        var key = new Dictionary<string, string> { ["key"] = Convert.ToBase64String(new byte[32]) };
        var data = "contrato"u8.ToArray();
        var fwd = alg.Forward(new ForwardInput(data, None, key));
        fwd.Data.ShouldBe(data);
        fwd.PublicParameters["macAlgorithm"].ShouldBe("HMAC-SHA256");
        fwd.PublicParameters["macHex"].ShouldBe(Hex.Lower(HmacSha256Algorithm.Compute(new byte[32], data)));

        alg.Inverse(new InverseInput(data, fwd.PublicParameters, None, key)).Valid.ShouldBe(true);
        var otherKey = new Dictionary<string, string> { ["key"] = Convert.ToBase64String(Enumerable.Repeat((byte)1, 32).ToArray()) };
        var res = alg.Inverse(new InverseInput(data, fwd.PublicParameters, None, otherKey));
        res.Valid.ShouldBe(false);
        res.Detail.ShouldBe("HMAC no coincide");
    }

    [Theory] // Estándar §4.2: key ≥ 32 bytes; E-PARAMS
    [InlineData(null)]
    [InlineData("no-base64!")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==")] // 28 bytes
    public void Hmac_rejects_missing_short_or_invalid_key(string? keyB64)
    {
        var alg = new HmacSha256Algorithm();
        var secrets = keyB64 is null ? None : new Dictionary<string, string> { ["key"] = keyB64 };
        Should.Throw<ProtocolException>(() => alg.Forward(new ForwardInput([], None, secrets))).Code.ShouldBe(ErrorCodes.Params);
    }

    [Fact] // Plan §1: no se ofrece HMAC-SHA512
    public void Hmac_rejects_sha512_variant()
    {
        var alg = new HmacSha256Algorithm();
        var key = new Dictionary<string, string> { ["key"] = Convert.ToBase64String(new byte[32]) };
        Should.Throw<ProtocolException>(() => alg.Forward(new ForwardInput([], new Dictionary<string, string> { ["macAlgorithm"] = "HMAC-SHA512" }, key)))
            .Code.ShouldBe(ErrorCodes.Params);
    }
}
