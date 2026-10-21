namespace SecureCorpPortal.Models;

/// <summary>
/// Tipos de evento de auditoria. O nome é gravado como texto no banco e no
/// campo "event_type" do log. Catálogo completo: docs/siem/event-catalog.md.
/// </summary>
public enum AuditEventType
{
    UserLogin,
    UserLoginFailed,
    UserLockedOut,
    UserLogout,
    UserCreated,
    UserUpdated,
    UserDeleted,
    RoleChanged,
    PasswordChanged,
    DocumentAccessed,
    DocumentCreated,
    DocumentUploaded,
    DocumentDownloaded,
    DocumentDeleted,
    AdminAction,
    AccessDenied
}

/// <summary>Severidade (escala única usada no banco e no log JSON).</summary>
public enum AuditSeverity
{
    Info,
    Low,
    Medium,
    High,
    Critical
}
