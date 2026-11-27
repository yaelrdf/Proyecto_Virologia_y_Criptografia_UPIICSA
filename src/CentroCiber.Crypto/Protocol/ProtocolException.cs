namespace CentroCiber.Crypto.Protocol;

/// <summary>
/// Error del protocolo con un código del Anexo B. <see cref="Exception.Message"/> es el
/// <c>detail</c> en español y nunca debe contener secretos.
/// </summary>
public sealed class ProtocolException : Exception
{
    public ProtocolException(string code, string detail)
        : base(detail)
    {
        Code = code;
    }

    public ProtocolException(string code, string detail, Exception inner)
        : base(detail, inner)
    {
        Code = code;
    }

    public ProtocolException()
        : this(ErrorCodes.Internal, "Error interno.")
    {
    }

    public ProtocolException(string message)
        : this(ErrorCodes.Internal, message)
    {
    }

    public ProtocolException(string message, Exception innerException)
        : this(ErrorCodes.Internal, message, innerException)
    {
    }

    public string Code { get; }

    public int HttpStatus => ErrorCodes.Get(Code).HttpStatus;
}
