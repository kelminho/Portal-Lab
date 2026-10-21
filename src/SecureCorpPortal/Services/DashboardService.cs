using Microsoft.EntityFrameworkCore;
using SecureCorpPortal.Configuration;
using SecureCorpPortal.Data;
using SecureCorpPortal.DTOs;
using SecureCorpPortal.Models;
using SecureCorpPortal.Repositories;

namespace SecureCorpPortal.Services;

public interface IDashboardService
{
    Task<DashboardDto> GetAsync(CurrentUser user, CancellationToken cancellationToken = default);
}

/// <summary>
/// Monta o dashboard. Indicadores de segurança (Analytics) só são calculados
/// para ADMIN/ANALYST e os eventos de auditoria recentes só para ADMIN —
/// cada papel recebe apenas os dados de que precisa.
/// </summary>
public sealed class DashboardService : IDashboardService
{
    private readonly AppDbContext _db;
    private readonly IDocumentRepository _documents;
    private readonly IAuditEventRepository _auditEvents;

    public DashboardService(AppDbContext db, IDocumentRepository documents, IAuditEventRepository auditEvents)
    {
        _db = db;
        _documents = documents;
        _auditEvents = auditEvents;
    }

    public async Task<DashboardDto> GetAsync(CurrentUser user, CancellationToken cancellationToken = default)
    {
        var appUser = await _db.Users.AsNoTracking().FirstAsync(u => u.Id == user.Id, cancellationToken);
        var visibility = DocumentAccessPolicy.VisibilityFor(user);

        var visibleDocuments = await _documents.CountVisibleAsync(visibility, cancellationToken);
        var myDocuments = await _documents.CountOwnedByAsync(user.Id, cancellationToken);
        var recentDocuments = await _documents.SearchVisibleAsync(visibility, null, 5, cancellationToken);
        var myActivity = await _auditEvents.GetRecentAsync(5, user.Id, cancellationToken);

        SecurityAnalyticsDto? analytics = null;
        if (user.IsAdmin || user.IsAnalyst)
        {
            analytics = await BuildAnalyticsAsync(cancellationToken);
        }

        IReadOnlyList<AuditEventDto>? recentAudit = null;
        if (user.IsAdmin)
        {
            recentAudit = (await _auditEvents.GetRecentAsync(10, null, cancellationToken))
                .Select(DtoMapper.ToDto)
                .ToList();
        }

        return new DashboardDto(
            DtoMapper.ToDto(appUser, user.Role),
            visibleDocuments,
            myDocuments,
            recentDocuments.Select(d => DtoMapper.ToDto(d, includeContent: false)).ToList(),
            myActivity.Select(DtoMapper.ToDto).ToList(),
            analytics,
            recentAudit);
    }

    private async Task<SecurityAnalyticsDto> BuildAnalyticsAsync(CancellationToken cancellationToken)
    {
        var since = DateTime.UtcNow.AddHours(-24);

        var totalUsers = await _db.Users.CountAsync(cancellationToken);
        var activeUsers = await _db.Users.CountAsync(u => u.IsActive, cancellationToken);

        var roleRows = await (from userRole in _db.UserRoles
                              join role in _db.Roles on userRole.RoleId equals role.Id
                              group userRole by role.Name into g
                              select new { Role = g.Key, Count = g.Count() })
            .ToListAsync(cancellationToken);

        var usersByRole = AppRoles.All.ToDictionary(
            r => r,
            r => roleRows.FirstOrDefault(x => x.Role == r)?.Count ?? 0);

        var byClassification = await _documents.CountByClassificationAsync(cancellationToken);
        var documentsByClassification = Enum.GetValues<DocumentClassification>().ToDictionary(
            c => c.ToString(),
            c => byClassification.TryGetValue(c, out var count) ? count : 0);

        return new SecurityAnalyticsDto(
            totalUsers,
            activeUsers,
            usersByRole,
            documentsByClassification,
            await _auditEvents.CountSinceAsync(AuditEventType.UserLogin, since, cancellationToken),
            await _auditEvents.CountSinceAsync(AuditEventType.UserLoginFailed, since, cancellationToken),
            await _auditEvents.CountSinceAsync(AuditEventType.UserLockedOut, since, cancellationToken),
            await _auditEvents.CountSinceAsync(AuditEventType.AccessDenied, since, cancellationToken));
    }
}
