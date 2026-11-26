using CentroCiber.Application.Jobs;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Packaging.Contracts;
using Microsoft.AspNetCore.Mvc;

namespace CentroCiber.Web.Api;

/// <summary><c>GET /api/jobs/{jobId}</c> y <c>/result</c> (§10.7).</summary>
[ApiController]
[Route("api/jobs")]
public sealed class JobsController(JobQueue jobs) : ControllerBase
{
    /// <summary>Estado del trabajo.</summary>
    [HttpGet("{jobId}")]
    [ProducesResponseType<JobStatusResponse>(StatusCodes.Status200OK, "application/json")]
    [ProducesResponseType<ProblemDocument>(StatusCodes.Status404NotFound, ProtocolConstants.ProblemContentType)]
    public JobStatusResponse Get(string jobId) => JobQueue.ToStatus(Find(jobId));

    /// <summary>Resultado; solo para el <c>requesterNode</c> original (encabezado <c>X-CC-Node</c>). ADR 0011.</summary>
    [HttpGet("{jobId}/result")]
    [ProducesResponseType<byte[]>(StatusCodes.Status200OK, ProtocolConstants.ZipContentType)]
    [ProducesResponseType<ProblemDocument>(StatusCodes.Status404NotFound, ProtocolConstants.ProblemContentType)]
    public IActionResult Result(string jobId)
    {
        var job = Find(jobId);
        var requester = Request.Headers[ProtocolConstants.HeaderNode].FirstOrDefault();
        if (!string.Equals(requester, job.RequesterNode, StringComparison.Ordinal) || job.State != ProtocolConstants.JobDone)
        {
            throw new ProtocolException(ErrorCodes.JobNotFound,
                job.State == ProtocolConstants.JobDone
                    ? "El resultado solo está disponible para el nodo solicitante (X-CC-Node)."
                    : "El trabajo todavía no tiene resultado.");
        }

        return File(job.ResultZip!, ProtocolConstants.ZipContentType, job.ResultFileName);
    }

    private ProviderJob Find(string jobId) =>
        (Identifiers.IsUuidV4(jobId) ? jobs.Get(jobId) : null)
        ?? throw new ProtocolException(ErrorCodes.JobNotFound, "jobId desconocido o expirado.");
}
