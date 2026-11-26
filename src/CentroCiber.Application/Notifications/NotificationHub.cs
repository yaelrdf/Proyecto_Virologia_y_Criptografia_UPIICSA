namespace CentroCiber.Application.Notifications;

/// <summary>Tipos de evento para la interfaz en tiempo real.</summary>
public enum NodeEventKind
{
    InboxReceived,
    JobCompleted,
    NodeDiscovered,
    ThumbprintChanged,
    NodeStatusChanged,
    PackageStored,
}

/// <summary>Evento que la interfaz muestra como notificación (sin secretos).</summary>
public sealed record NodeEvent(NodeEventKind Kind, string Message, DateTimeOffset AtUtc, string? NodeId = null);

/// <summary>
/// Concentrador en memoria: los servicios publican y los componentes Blazor se suscriben;
/// el circuito SignalR de Blazor Server lleva la actualización al navegador.
/// </summary>
public sealed class NotificationHub
{
    private readonly Lock gate = new();
    private readonly List<NodeEvent> recent = [];

    public event Action<NodeEvent>? Published;

    public IReadOnlyList<NodeEvent> Recent
    {
        get
        {
            lock (gate)
            {
                return recent.ToArray();
            }
        }
    }

    public void Publish(NodeEvent e)
    {
        lock (gate)
        {
            recent.Insert(0, e);
            if (recent.Count > 50)
            {
                recent.RemoveAt(recent.Count - 1);
            }
        }

        Published?.Invoke(e);
    }
}
