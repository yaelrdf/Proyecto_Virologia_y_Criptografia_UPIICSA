using CentroCiber.Crypto.Protocol;

namespace CentroCiber.Crypto.Algorithms;

/// <summary>Validación de opciones y secretos según el perfil (§13.2 #8 → <c>E-PARAMS</c>).</summary>
public static class ParameterRules
{
    public static void AllowOnly(IReadOnlyDictionary<string, string> values, params string[] allowed)
    {
        foreach (var key in values.Keys)
        {
            if (!allowed.Contains(key, StringComparer.Ordinal))
            {
                throw new ProtocolException(ErrorCodes.Params, $"Parámetro no reconocido: {key}.");
            }
        }
    }

    public static void RejectSecrets(IReadOnlyDictionary<string, string> secrets, string algorithmCode)
    {
        if (secrets.Count > 0)
        {
            throw new ProtocolException(ErrorCodes.Params, $"{algorithmCode} no usa secretos.");
        }
    }

    public static string Require(IReadOnlyDictionary<string, string> values, string key) =>
        values.TryGetValue(key, out var v) && !string.IsNullOrEmpty(v)
            ? v
            : throw new ProtocolException(ErrorCodes.Params, $"Falta el parámetro {key}.");
}
