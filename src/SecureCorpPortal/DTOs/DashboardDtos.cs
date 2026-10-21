namespace SecureCorpPortal.DTOs;

/// <summary>
/// Dados do dashboard. O conteúdo varia conforme o papel:
/// - todos: resumo pessoal e documentos recentes visíveis;
/// - ADMIN/ANALYST: Analytics (indicadores de segurança agregados);
/// - ADMIN: RecentAuditEvents (últimos eventos de auditoria).
/// </summary>
public sealed record DashboardDto(
    UserDto User,
    int VisibleDocuments,
    int MyDocuments,
    IReadOnlyList<DocumentDto> RecentDocuments,
    IReadOnlyList<AuditEventDto> MyRecentActivity,
    SecurityAnalyticsDto? Analytics,
    IReadOnlyList<AuditEventDto>? RecentAuditEvents);

/// <summary>Indicadores das últimas 24 horas + contagens gerais.</summary>
public sealed record SecurityAnalyticsDto(
    int TotalUsers,
    int ActiveUsers,
    IReadOnlyDictionary<string, int> UsersByRole,
    IReadOnlyDictionary<string, int> DocumentsByClassification,
    int SuccessfulLogins24h,
    int FailedLogins24h,
    int Lockouts24h,
    int AccessDenied24h);
