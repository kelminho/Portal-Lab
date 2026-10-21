namespace SecureCorpPortal.Models;

/// <summary>
/// Evento de auditoria (trilha de negócio), gravado no banco e também emitido
/// no log JSON. Intencionalmente SEM chave estrangeira para users: a trilha
/// precisa continuar existindo mesmo após a exclusão de um usuário.
/// Tabela: audit_events.
/// </summary>
public class AuditEvent
{
    public long Id { get; set; }

    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    public AuditEventType EventType { get; set; }

    /// <summary>Ação específica, em formato "recurso.verbo" (ex.: "user.role_changed").</summary>
    public string Action { get; set; } = string.Empty;

    public bool Success { get; set; }

    public AuditSeverity Severity { get; set; } = AuditSeverity.Info;

    /// <summary>Usuário que executou a ação (ou que tentou autenticar).</summary>
    public int? UserId { get; set; }

    public string? Username { get; set; }

    public string? SourceIp { get; set; }

    public string? UserAgent { get; set; }

    public string? HttpMethod { get; set; }

    public string? Endpoint { get; set; }

    /// <summary>Recurso afetado (ex.: "document:12", "user:5").</summary>
    public string? Resource { get; set; }

    /// <summary>Texto descritivo. NUNCA deve conter senhas, tokens ou segredos.</summary>
    public string? Details { get; set; }

    /// <summary>Mesmo request_id presente no log técnico, para correlação.</summary>
    public string? RequestId { get; set; }
}
