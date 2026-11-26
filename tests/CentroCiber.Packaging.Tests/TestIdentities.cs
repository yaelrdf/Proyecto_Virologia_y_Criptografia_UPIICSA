using CentroCiber.Crypto.Identity;
using Microsoft.Extensions.Time.Testing;

namespace CentroCiber.Packaging.Tests;

/// <summary>Identidades compartidas (generar RSA-2048 es costoso). Creadas el 24/11/2026 para el reloj simulado.</summary>
public static class TestIdentities
{
    private static readonly FakeTimeProvider Past = new(new DateTimeOffset(2026, 11, 24, 15, 47, 0, TimeSpan.Zero));

    public static NodeIdentity Eq08 { get; } = NodeIdentity.Create(8, Past);

    public static NodeIdentity Eq01 { get; } = NodeIdentity.Create(1, Past);
}
