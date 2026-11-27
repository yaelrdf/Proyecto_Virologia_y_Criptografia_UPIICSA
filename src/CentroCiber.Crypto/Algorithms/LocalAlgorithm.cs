namespace CentroCiber.Crypto.Algorithms;

/// <summary>Entrada de <c>forward</c>: datos, opciones públicas y secretos (todos cadenas, §4.2).</summary>
public sealed record ForwardInput(
    byte[] Data,
    IReadOnlyDictionary<string, string> Options,
    IReadOnlyDictionary<string, string> Secrets);

/// <summary>Salida de <c>forward</c>: contenido de <c>datos.enc</c> y <c>publicParameters</c>.</summary>
public sealed record ForwardOutput(byte[] Data, IReadOnlyDictionary<string, string> PublicParameters, string AlgorithmName);

/// <summary>Entrada de <c>inverse</c>: contenido de <c>datos.enc</c>, parámetros públicos del manifiesto y secretos.</summary>
public sealed record InverseInput(
    byte[] Data,
    IReadOnlyDictionary<string, string> PublicParameters,
    IReadOnlyDictionary<string, string> Options,
    IReadOnlyDictionary<string, string> Secrets);

/// <summary>Salida de <c>inverse</c>: original recuperado y, para hash/MAC, el veredicto.</summary>
public sealed record InverseOutput(byte[] Original, bool? Valid, string? Detail, string AlgorithmName);

/// <summary>Algoritmo ejecutado localmente por este nodo (lógica pura, sin red ni paquetes).</summary>
public interface ILocalAlgorithm
{
    string Code { get; }

    /// <summary>Variantes ofrecidas (p. ej. <c>SHA-256</c>, <c>SHA-512</c>).</summary>
    IReadOnlyList<string> Variants { get; }

    ForwardOutput Forward(ForwardInput input);

    InverseOutput Inverse(InverseInput input);
}
