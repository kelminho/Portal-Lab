using SecureCorpPortal.Models;

namespace SecureCorpPortal.Services;

/// <summary>
/// Severidade padrão de cada tipo de evento. Falhas são no mínimo "Medium".
/// Tabela documentada em docs/siem/event-catalog.md.
/// </summary>
public static class AuditSeverityDefaults
{
    public static AuditSeverity For(AuditEventType eventType, bool success)
    {
        var severity = eventType switch
        {
            AuditEventType.UserLogin => AuditSeverity.Info,
            AuditEventType.UserLogout => AuditSeverity.Info,
            AuditEventType.UserLoginFailed => AuditSeverity.Medium,
            AuditEventType.UserLockedOut => AuditSeverity.High,
            AuditEventType.UserCreated => AuditSeverity.Low,
            AuditEventType.UserUpdated => AuditSeverity.Low,
            AuditEventType.UserDeleted => AuditSeverity.High,
            AuditEventType.RoleChanged => AuditSeverity.High,
            AuditEventType.PasswordChanged => AuditSeverity.Medium,
            AuditEventType.DocumentAccessed => AuditSeverity.Info,
            AuditEventType.DocumentDownloaded => AuditSeverity.Info,
            AuditEventType.DocumentCreated => AuditSeverity.Low,
            AuditEventType.DocumentUploaded => AuditSeverity.Low,
            AuditEventType.DocumentDeleted => AuditSeverity.Medium,
            AuditEventType.AdminAction => AuditSeverity.Medium,
            AuditEventType.AccessDenied => AuditSeverity.Medium,
            _ => AuditSeverity.Info
        };

        return !success && severity < AuditSeverity.Medium ? AuditSeverity.Medium : severity;
    }
}
