using SecureCorpPortal.DTOs;
using SecureCorpPortal.Models;

namespace SecureCorpPortal.Services;

/// <summary>
/// Dados de um evento de auditoria a ser registrado. Campos de contexto HTTP
/// (IP, user agent, endpoint, request_id) são preenchidos automaticamente.
/// UserId/Username só precisam ser informados quando o usuário ainda não está
/// autenticado na requisição (ex.: login).
/// </summary>
public sealed record AuditEntry(AuditEventType EventType, string Action, bool Success = true)
{
    public string? Resource { get; init; }

    public string? Details { get; init; }

    public int? UserId { get; init; }

    public string? Username { get; init; }

    /// <summary>Se nulo, usa AuditSeverityDefaults.</summary>
    public AuditSeverity? Severity { get; init; }
}

public interface IAuditService
{
    /// <summary>Grava no banco (tabela audit_events) e emite no log JSON.</summary>
    Task RecordAsync(AuditEntry entry, CancellationToken cancellationToken = default);

    Task<PagedResult<AuditEventDto>> QueryAsync(AuditQuery query, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<AuditEventDto>> GetRecentAsync(int take, int? userId = null, CancellationToken cancellationToken = default);
}
