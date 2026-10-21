using System.ComponentModel.DataAnnotations;
using SecureCorpPortal.Models;

namespace SecureCorpPortal.DTOs;

public sealed record AuditEventDto(
    long Id,
    DateTime Timestamp,
    AuditEventType EventType,
    string Action,
    bool Success,
    AuditSeverity Severity,
    int? UserId,
    string? Username,
    string? SourceIp,
    string? UserAgent,
    string? HttpMethod,
    string? Endpoint,
    string? Resource,
    string? Details,
    string? RequestId);

/// <summary>
/// Filtros da consulta de auditoria (query string). Datas são interpretadas como UTC.
/// Ex.: /api/admin/logs?eventType=UserLoginFailed&amp;from=2026-01-01T00:00&amp;page=1&amp;pageSize=50
/// </summary>
public sealed class AuditQuery
{
    public AuditEventType? EventType { get; set; }

    public AuditSeverity? Severity { get; set; }

    [StringLength(256)]
    public string? Username { get; set; }

    public bool? Success { get; set; }

    public DateTime? From { get; set; }

    public DateTime? To { get; set; }

    [Range(1, int.MaxValue)]
    public int Page { get; set; } = 1;

    [Range(1, 200)]
    public int PageSize { get; set; } = 50;
}

public sealed record PagedResult<T>(IReadOnlyList<T> Items, int Page, int PageSize, int TotalCount)
{
    public int TotalPages => PageSize == 0 ? 0 : (int)Math.Ceiling(TotalCount / (double)PageSize);

    public bool HasPrevious => Page > 1;

    public bool HasNext => Page < TotalPages;
}
