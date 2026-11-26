using CentroCiber.Crypto.Protocol;
using CentroCiber.Infrastructure.Configuration;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace CentroCiber.Web.Api;

/// <summary>§10.3 <c>GET /api/status</c>.</summary>
[ApiController]
[Route("api/status")]
public sealed class StatusController(IOptions<NodeOptions> options, TimeProvider clock) : ControllerBase
{
    [HttpGet]
    public IActionResult Get()
    {
        var o = options.Value;
        return Ok(new
        {
            nodeId = o.NodeId,
            teamNumber = o.TeamNumber,
            protocolVersion = ProtocolConstants.ProtocolVersion,
            status = ProtocolConstants.StatusOnline,
            acceptingPackages = true,
            httpPort = o.EffectiveHttpPort,
            httpsPort = o.HttpsEnabled ? o.EffectiveHttpsPort : (int?)null,
            algorithms = AlgorithmCatalog.OwnedBy(o.TeamNumber).Select(a => new { algorithmId = a.Id, algorithmCode = a.Code }),
            certificateThumbprintSha256 = string.Empty,
            serverTimeUtc = Identifiers.FormatTimestamp(clock.GetUtcNow()),
        });
    }
}
