using CentroCiber.Application;
using CentroCiber.Application.Providers;
using CentroCiber.Application.Services;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Packaging.Contracts;
using Microsoft.AspNetCore.Mvc;

namespace CentroCiber.Web.Api;

/// <summary><c>GET /api/status</c>, <c>/api/certificate</c>, <c>/api/algorithms</c> y <c>/api/keys/{keyId}</c>.</summary>
[ApiController]
[Route("api")]
public sealed class NodeController(NodeContext node, LocalAlgorithmProvider local, SettingsService settings) : ControllerBase
{
    /// <summary>Estado del nodo (§10.3).</summary>
    [HttpGet("status")]
    [ProducesResponseType<StatusResponse>(StatusCodes.Status200OK, "application/json")]
    public async Task<StatusResponse> Status(CancellationToken ct)
    {
        var s = await settings.GetAsync(ct);
        return new StatusResponse
        {
            NodeId = node.NodeId,
            TeamNumber = node.TeamNumber,
            ProtocolVersion = ProtocolConstants.ProtocolVersion,
            Status = ProtocolConstants.StatusOnline,
            AcceptingPackages = s.AcceptingPackages,
            HttpPort = node.HttpPort,
            HttpsPort = node.HttpsPort,
            Algorithms = local.Algorithms
                .Select(a => AlgorithmCatalog.ByCode(a.Code)!)
                .OrderBy(a => a.Id)
                .Select(a => new StatusAlgorithm(a.Id, a.Code)).ToList(),
            CertificateThumbprintSha256 = node.Identity.Thumbprint,
            ServerTimeUtc = Identifiers.FormatTimestamp(node.Clock.GetUtcNow()),
            SupportedProtocolVersions = [ProtocolConstants.ProtocolVersion],
            NodeVersion = NodeVersionInfo.Current,
        };
    }

    /// <summary>Certificado de identidad en PEM (§10.2).</summary>
    [HttpGet("certificate")]
    [Produces(ProtocolConstants.PemContentType)]
    [ProducesResponseType<string>(StatusCodes.Status200OK, ProtocolConstants.PemContentType)]
    public ContentResult Certificate() => Content(node.Identity.CertificatePem, ProtocolConstants.PemContentType);

    /// <summary>Perfiles de los algoritmos propios (§10.4).</summary>
    [HttpGet("algorithms")]
    [ProducesResponseType<AlgorithmsResponse>(StatusCodes.Status200OK, "application/json")]
    public async Task<AlgorithmsResponse> Algorithms(CancellationToken ct)
    {
        var enabled = await settings.EnabledVariantsAsync(ct);
        return new AlgorithmsResponse(node.NodeId, local.Algorithms
            .OrderBy(a => AlgorithmCatalog.ByCode(a.Code)!.Id)
            .Select(a => AlgorithmProfiles.For(a, enabled)).ToList());
    }

    /// <summary>EQ08 no tiene algoritmos con <c>keyId</c> (§12): siempre <c>404 E-KEY-NOT-FOUND</c>.</summary>
    [HttpGet("keys/{keyId}")]
    [ProducesResponseType<ProblemDocument>(StatusCodes.Status404NotFound, ProtocolConstants.ProblemContentType)]
    public IActionResult Key(string keyId) =>
        throw new ProtocolException(ErrorCodes.KeyNotFound, $"{node.NodeId} no guarda llaves; keyId desconocido: {keyId}.");
}

/// <summary>Versión del producto (de <c>Directory.Build.props</c>).</summary>
public static class NodeVersionInfo
{
    public static string Current { get; } =
        typeof(NodeVersionInfo).Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
            .OfType<System.Reflection.AssemblyInformationalVersionAttribute>().FirstOrDefault()?.InformationalVersion.Split('+')[0]
        ?? typeof(NodeVersionInfo).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
}
