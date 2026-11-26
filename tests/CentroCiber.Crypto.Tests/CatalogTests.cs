using CentroCiber.Crypto.Protocol;

namespace CentroCiber.Crypto.Tests;

public class CatalogTests
{
    [Fact] // Estándar §4.1
    public void Catalog_has_the_21_official_algorithms_in_order()
    {
        AlgorithmCatalog.All.Count.ShouldBe(21);
        AlgorithmCatalog.All.Select(a => a.Id).ShouldBe(Enumerable.Range(1, 21));
        AlgorithmCatalog.All.ShouldAllBe(a => a.Code == a.Code.ToUpperInvariant() && !a.Code.Contains('-'));
    }

    [Fact] // Estándar §4.1: EQ08 es dueño de 15 y 16
    public void Team_8_owns_HASHSHA_and_HMACSHA256()
    {
        AlgorithmCatalog.OwnedBy(8).Select(a => a.Code).ShouldBe(["HASHSHA", "HMACSHA256"]);
        AlgorithmCatalog.ByCode("HASHSHA")!.OwnerNodeId.ShouldBe("EQ08");
    }

    [Fact] // Estándar §4.1: 17–21 reservados
    public void Algorithms_17_to_21_are_reserved()
    {
        AlgorithmCatalog.All.Where(a => a.IsReserved).Select(a => a.Id).ShouldBe([17, 18, 19, 20, 21]);
        AlgorithmCatalog.AssignedTeams.ShouldBe([1, 2, 3, 4, 5, 6, 7, 8]);
    }

    [Theory] // Estándar §13.1 #7
    [InlineData(15, "HASHSHA", true)]
    [InlineData(16, "HASHSHA", false)]
    [InlineData(22, "HASHSHA", false)]
    [InlineData(1, "aesgcm", false)]
    public void Id_and_code_consistency(int id, string code, bool expected) =>
        AlgorithmCatalog.IsConsistent(id, code).ShouldBe(expected);

    [Fact] // Estándar §5.1
    public void Ports_are_derived_from_team_number()
    {
        ProtocolConstants.HttpPortFor(8).ShouldBe(5008);
        ProtocolConstants.HttpsPortFor(8).ShouldBe(5108);
        ProtocolConstants.NodeIdFor(8).ShouldBe("EQ08");
    }

    [Fact] // Anexo B
    public void Error_catalog_has_29_codes()
    {
        ErrorCodes.Catalog.Count.ShouldBe(29);
        ErrorCodes.Get(ErrorCodes.Hash).HttpStatus.ShouldBe(422);
        ErrorCodes.Get(ErrorCodes.Size).HttpStatus.ShouldBe(413);
    }

    [Theory] // Estándar §3
    [InlineData("EQ08", true)]
    [InlineData("EQ8", false)]
    [InlineData("eq08", false)]
    public void NodeId_format(string value, bool ok) => Identifiers.IsNodeId(value).ShouldBe(ok);

    [Fact] // Estándar §3
    public void Uuid_and_timestamp_formats()
    {
        Identifiers.IsUuidV4(Identifiers.NewUuid()).ShouldBeTrue();
        Identifiers.IsUuidV4("550E8400-E29B-41D4-A716-446655440000").ShouldBeFalse();
        Identifiers.IsTimestamp("2026-11-25T15:47:00Z").ShouldBeTrue();
        Identifiers.IsTimestamp("2026-11-25T15:47:00.123Z").ShouldBeFalse();
        Identifiers.IsTimestamp("2026-13-25T15:47:00Z").ShouldBeFalse();
        Identifiers.IsKeyId("EQ03-KEY-1f0c2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b").ShouldBeTrue();
    }
}
