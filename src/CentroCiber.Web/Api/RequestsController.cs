using CentroCiber.Application.Services;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Packaging.Contracts;
using Microsoft.AspNetCore.Mvc;

namespace CentroCiber.Web.Api;

/// <summary><c>POST /api/requests/receive</c> (§10.5): bandeja de Solicitudes.</summary>
[ApiController]
[Route("api/requests")]
public sealed class RequestsController(InboxService inbox) : ControllerBase
{
    /// <summary>Recibe un paquete en la parte <c>package</c> del multipart.</summary>
    [HttpPost("receive")]
    [Consumes("multipart/form-data")]
    [ProducesResponseType<ReceiveResponse>(StatusCodes.Status202Accepted, "application/json")]
    [ProducesResponseType<ProblemDocument>(StatusCodes.Status400BadRequest, ProtocolConstants.ProblemContentType)]
    [ProducesResponseType<ProblemDocument>(StatusCodes.Status409Conflict, ProtocolConstants.ProblemContentType)]
    [ProducesResponseType<ProblemDocument>(StatusCodes.Status413PayloadTooLarge, ProtocolConstants.ProblemContentType)]
    [ProducesResponseType<ProblemDocument>(StatusCodes.Status422UnprocessableEntity, ProtocolConstants.ProblemContentType)]
    public async Task<IActionResult> Receive(CancellationToken ct)
    {
        var form = await ProtocolApi.ReadFormAsync(Request, ct);
        var zip = await ProtocolApi.ReadPartAsync(form, ProtocolConstants.PartPackage, ct)
            ?? throw new ProtocolException(ErrorCodes.Request, "Falta la parte 'package' con el .zip.");
        var remote = HttpContext.Connection.RemoteIpAddress;
        var remoteIp = remote is null ? null : $"{(remote.IsIPv4MappedToIPv6 ? remote.MapToIPv4() : remote)}";
        var response = await inbox.ReceiveAsync(zip, remoteIp, ct);
        HttpContext.Items[ProtocolApi.RequestIdItem] = response.PacketId;
        return StatusCode(StatusCodes.Status202Accepted, response);
    }
}
