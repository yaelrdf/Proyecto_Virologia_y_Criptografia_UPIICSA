using System.Text;
using CentroCiber.Application.Services;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Packaging.Contracts;
using Microsoft.AspNetCore.Mvc;

namespace CentroCiber.Web.Api;

/// <summary><c>POST /api/crypto/forward</c> e <c>inverse</c> (§10.6).</summary>
[ApiController]
[Route("api/crypto")]
public sealed class CryptoController(CryptoRequestHandler handler) : ControllerBase
{
    /// <summary>Ejecuta <c>forward</c> de un algoritmo propio: 200 con <c>package</c> o 202 con <c>jobId</c>.</summary>
    [HttpPost("forward")]
    [Consumes("multipart/form-data")]
    [ProducesResponseType<byte[]>(StatusCodes.Status200OK, ProtocolConstants.ZipContentType)]
    [ProducesResponseType<JobAccepted>(StatusCodes.Status202Accepted, "application/json")]
    [ProducesResponseType<ProblemDocument>(StatusCodes.Status400BadRequest, ProtocolConstants.ProblemContentType)]
    [ProducesResponseType<ProblemDocument>(StatusCodes.Status401Unauthorized, ProtocolConstants.ProblemContentType)]
    [ProducesResponseType<ProblemDocument>(StatusCodes.Status404NotFound, ProtocolConstants.ProblemContentType)]
    [ProducesResponseType<ProblemDocument>(StatusCodes.Status503ServiceUnavailable, ProtocolConstants.ProblemContentType)]
    public Task<IActionResult> Forward(CancellationToken ct) => Handle(ProtocolConstants.OperationForward, ct);

    /// <summary>Ejecuta <c>inverse</c>: 200 con <c>result</c> cifrado para el solicitante o 202 con <c>jobId</c>.</summary>
    [HttpPost("inverse")]
    [Consumes("multipart/form-data")]
    [ProducesResponseType<byte[]>(StatusCodes.Status200OK, ProtocolConstants.ZipContentType)]
    [ProducesResponseType<JobAccepted>(StatusCodes.Status202Accepted, "application/json")]
    [ProducesResponseType<ProblemDocument>(StatusCodes.Status400BadRequest, ProtocolConstants.ProblemContentType)]
    [ProducesResponseType<ProblemDocument>(StatusCodes.Status401Unauthorized, ProtocolConstants.ProblemContentType)]
    [ProducesResponseType<ProblemDocument>(StatusCodes.Status422UnprocessableEntity, ProtocolConstants.ProblemContentType)]
    public Task<IActionResult> Inverse(CancellationToken ct) => Handle(ProtocolConstants.OperationInverse, ct);

    private async Task<IActionResult> Handle(string operation, CancellationToken ct)
    {
        var form = await ProtocolApi.ReadFormAsync(Request, ct);
        var requestBytes = await ProtocolApi.ReadPartAsync(form, ProtocolConstants.PartRequest, ct);
        var signature = await ProtocolApi.ReadPartAsync(form, ProtocolConstants.PartRequestSignature, ct);
        var cert = await ProtocolApi.ReadPartAsync(form, ProtocolConstants.PartRequesterCertificate, ct);
        var header = Request.Headers[ProtocolConstants.HeaderRequestId].FirstOrDefault();
        if (header is not null)
        {
            HttpContext.Items[ProtocolApi.RequestIdItem] = header;
        }

        var remote = HttpContext.Connection.RemoteIpAddress;
        var response = await handler.HandleAsync(new IncomingCryptoRequest
        {
            Operation = operation,
            RequestBytes = requestBytes,
            RequestSignature = signature is null ? null : Encoding.ASCII.GetString(signature).Trim(),
            RequesterCertificatePem = cert is null ? null : Encoding.ASCII.GetString(cert),
            Payload = await ProtocolApi.ReadPartAsync(form, ProtocolConstants.PartPayload, ct),
            Cover = await ProtocolApi.ReadPartAsync(form, ProtocolConstants.PartCover, ct),
            Package = await ProtocolApi.ReadPartAsync(form, ProtocolConstants.PartPackage, ct),
            RemoteIp = remote is null ? null : (remote.IsIPv4MappedToIPv6 ? remote.MapToIPv4() : remote).ToString(),
        }, ct);
        HttpContext.Items[ProtocolApi.RequestIdItem] = response.RequestId;
        Response.Headers[ProtocolConstants.HeaderRequestId] = response.RequestId;
        if (response.Job is { } job)
        {
            return StatusCode(StatusCodes.Status202Accepted, job);
        }

        return File(response.Zip!, ProtocolConstants.ZipContentType, response.FileName);
    }
}
