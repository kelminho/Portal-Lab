namespace SecureCorpPortal.Logging;

/// <summary>
/// Nomes dos campos do log JSON. Centralizar os nomes evita divergências
/// (ex.: "userId" x "user_id") que atrapalham a ingestão no SIEM.
/// Esquema completo: docs/siem/log-schema.md.
/// </summary>
public static class LogFields
{
    public const string Timestamp = "timestamp";
    public const string Severity = "severity";
    public const string RequestId = "request_id";
    public const string SourceIp = "source_ip";
    public const string Username = "username";
    public const string UserId = "user_id";
    public const string HttpMethod = "http_method";
    public const string Endpoint = "endpoint";
    public const string QueryString = "query_string";
    public const string StatusCode = "status_code";
    public const string DurationMs = "duration_ms";
    public const string UserAgent = "user_agent";
    public const string Action = "action";
    public const string EventType = "event_type";
    public const string EventCategory = "event_category";
    public const string Outcome = "outcome";
    public const string Resource = "resource";
}

/// <summary>Valores do campo event_category.</summary>
public static class EventCategories
{
    /// <summary>Trilha de auditoria de negócio (também gravada no banco).</summary>
    public const string Audit = "audit";

    /// <summary>Eventos de segurança técnicos (ex.: acesso sem autenticação).</summary>
    public const string Security = "security";

    /// <summary>Uma linha por requisição HTTP.</summary>
    public const string Http = "http";

    /// <summary>Ciclo de vida da aplicação, erros e exceções.</summary>
    public const string Application = "application";
}

/// <summary>Tipos de evento técnicos (os de auditoria estão em Models/AuditEventType.cs).</summary>
public static class TechnicalEventTypes
{
    public const string HttpRequest = "HttpRequest";
    public const string ApplicationError = "ApplicationError";
    public const string AuthenticationRequired = "AuthenticationRequired";
    public const string DatabaseInitialization = "DatabaseInitialization";
    public const string AuditPersistenceFailed = "AuditPersistenceFailed";
}
