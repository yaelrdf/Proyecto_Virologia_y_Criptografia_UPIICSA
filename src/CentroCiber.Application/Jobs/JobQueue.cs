using System.Collections.Concurrent;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Packaging.Contracts;

namespace CentroCiber.Application.Jobs;

/// <summary>Trabajo asíncrono del proveedor (§10.6–10.7).</summary>
public sealed class ProviderJob
{
    public required string JobId { get; init; }

    public required string RequesterNode { get; init; }

    public required string RequestId { get; init; }

    public required DateTimeOffset CreatedUtc { get; init; }

    public string State { get; set; } = ProtocolConstants.JobRunning;

    public int ProgressPercent { get; set; }

    public byte[]? ResultZip { get; set; }

    public string? ResultFileName { get; set; }

    public JobError? Error { get; set; }

    public DateTimeOffset? CompletedUtc { get; set; }
}

/// <summary>
/// Cola de trabajos en memoria. Se conservan los resultados al menos 1 h (§10.7);
/// <see cref="Purge"/> elimina los terminados hace más de la retención.
/// </summary>
public sealed class JobQueue(TimeProvider clock)
{
    private readonly ConcurrentDictionary<string, ProviderJob> jobs = new(StringComparer.Ordinal);

    public TimeSpan Retention { get; init; } = ProtocolConstants.JobRetention;

    /// <summary>Registra un trabajo que ya está corriendo y lo completa cuando termine la tarea.</summary>
    public ProviderJob Track(string requesterNode, string requestId, Task<(byte[] Zip, string FileName)> work, Action<ProviderJob>? onCompleted = null)
    {
        var job = new ProviderJob
        {
            JobId = Identifiers.NewUuid(),
            RequesterNode = requesterNode,
            RequestId = requestId,
            CreatedUtc = clock.GetUtcNow(),
            ProgressPercent = 50,
        };
        jobs[job.JobId] = job;
        _ = work.ContinueWith(t =>
        {
            if (t.IsCompletedSuccessfully)
            {
                job.ResultZip = t.Result.Zip;
                job.ResultFileName = t.Result.FileName;
                job.ProgressPercent = 100;
                job.State = ProtocolConstants.JobDone;
            }
            else
            {
                var ex = t.Exception?.GetBaseException() as ProtocolException
                    ?? new ProtocolException(ErrorCodes.Internal, "Error interno al ejecutar el trabajo.");
                job.Error = new JobError(ex.Code, ex.Message);
                job.State = ProtocolConstants.JobFailed;
            }

            job.CompletedUtc = clock.GetUtcNow();
            onCompleted?.Invoke(job);
        }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        return job;
    }

    public ProviderJob? Get(string jobId)
    {
        Purge();
        return jobs.TryGetValue(jobId, out var job) ? job : null;
    }

    public int Purge()
    {
        var now = clock.GetUtcNow();
        var removed = 0;
        foreach (var (id, job) in jobs)
        {
            if (job.CompletedUtc is { } done && now - done > Retention && jobs.TryRemove(id, out _))
            {
                removed++;
            }
        }

        return removed;
    }

    public static JobStatusResponse ToStatus(ProviderJob job) => new()
    {
        JobId = job.JobId,
        State = job.State,
        ProgressPercent = job.ProgressPercent,
        ResultUrl = job.State == ProtocolConstants.JobDone ? $"/api/jobs/{job.JobId}/result" : null,
        Error = job.Error,
    };
}
