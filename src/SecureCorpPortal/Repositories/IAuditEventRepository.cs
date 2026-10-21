using SecureCorpPortal.DTOs;
using SecureCorpPortal.Models;

namespace SecureCorpPortal.Repositories;

public interface IAuditEventRepository
{
    Task AddAsync(AuditEvent auditEvent, CancellationToken cancellationToken = default);

    Task<(IReadOnlyList<AuditEvent> Items, int TotalCount)> QueryAsync(
        AuditQuery query, CancellationToken cancellationToken = default);

    Task<int> CountSinceAsync(AuditEventType eventType, DateTime sinceUtc, CancellationToken cancellationToken = default);

    /// <summary>Eventos mais recentes; se userId for informado, apenas os desse usuário.</summary>
    Task<IReadOnlyList<AuditEvent>> GetRecentAsync(int take, int? userId = null, CancellationToken cancellationToken = default);
}
