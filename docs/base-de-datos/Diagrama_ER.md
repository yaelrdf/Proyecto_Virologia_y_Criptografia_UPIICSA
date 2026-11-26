# Diagrama entidad-relación

Las relaciones son **lógicas**, por identificador del protocolo. No se declaran llaves foráneas en SQLite, porque los registros de otros nodos pueden llegar antes que el nodo al directorio, y porque los paquetes conservan su historial aunque el nodo se borre del directorio.

```mermaid
erDiagram
    Teams ||--o{ Algorithms : "es dueño de (OwnerTeam)"
    Teams ||--o| Nodes : "nodeId EQnn"
    Nodes ||--o{ Requests : "envía (SourceNode)"
    Nodes ||--o{ Packages : "produce (ProducerNode) / envía (SourceNode)"
    Nodes ||--o{ RemoteOperations : "contraparte (PeerNode)"
    Algorithms ||--o{ Packages : "AlgorithmCode"
    Algorithms ||--o{ Requests : "AlgorithmCode"
    Requests |o--o| Packages : "al aceptar (PackageId)"
    RemoteOperations |o--o| Packages : "resultado (ResultPackageId)"
    Packages ||--o| SeenIds : "packet:<packetId>"
    RemoteOperations ||--o| SeenIds : "request:<requestId>"

    Algorithms {
        int Id PK "algorithmId 1-21"
        string Code UK "algorithmCode"
        string Name
        string Category
        int OwnerTeam "nulo = reservado"
        string ForwardName
        string InverseName
        string KeyKind
    }
    Teams {
        int TeamNumber PK
        string NodeId UK
        int HttpPort
        int HttpsPort
        string AlgorithmCodes
    }
    Nodes {
        int Id PK
        string NodeId UK
        int TeamNumber
        string Ip
        int HttpPort
        int HttpsPort
        string PinnedThumbprintSha256
        string ObservedThumbprintSha256
        string CertificatePem
        string Algorithms
        string Source
        string Status
        string TrustState
        bool IsSelf
        datetime LastSeenUtc
        string ProfileJson
        string LastError
    }
    Packages {
        int Id PK
        string PacketId UK
        string FileName
        string Origin
        string PacketType
        string AlgorithmCode
        string Operation
        string SourceNode
        string ProducerNode
        string RequestId
        string EncryptedSha256
        string KeyId
        string KeyOwnerNode
        string StoragePath
        string ManifestJson
        bool VerificationValid
        bool IsSample
        datetime CreatedUtc
    }
    Requests {
        int Id PK
        string PacketId
        string SourceNode
        string SourceIp
        string FileName
        string AlgorithmCode
        string OperationName
        string ValidationResult
        string Status
        string ErrorCode
        string StoragePath
        int PackageId
        datetime ReceivedUtc
    }
    RemoteOperations {
        int Id PK
        string RequestId
        string Direction
        string PeerNode
        string AlgorithmCode
        string Operation
        string JobId
        string State
        string ErrorCode
        int ResultPackageId
    }
    SeenIds {
        string Id PK "kind:uuid"
        string Kind
        datetime SeenUtc
    }
    Settings {
        int Id PK "siempre 1"
        string EnabledVariants
        bool HttpsEnabled
        bool AcceptingPackages
        long MaxPayloadBytes
        string PfxFileName
    }
    AuditLog {
        long Id PK
        datetime TimestampUtc
        string Event
        string NodeId
        string Code
        string Detail
    }
```
