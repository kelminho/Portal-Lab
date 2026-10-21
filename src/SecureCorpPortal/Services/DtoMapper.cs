using SecureCorpPortal.DTOs;
using SecureCorpPortal.Models;

namespace SecureCorpPortal.Services;

/// <summary>Conversões entidade → DTO (mapeamento manual, sem bibliotecas).</summary>
public static class DtoMapper
{
    public static UserDto ToDto(ApplicationUser user, string role) => new(
        user.Id,
        user.UserName ?? string.Empty,
        user.Email ?? string.Empty,
        user.FullName,
        user.Department,
        user.JobTitle,
        role,
        user.IsActive,
        user.CreatedAt,
        user.LastLoginAt);

    public static AdminUserDto ToAdminDto(ApplicationUser user, string role) => new(
        user.Id,
        user.UserName ?? string.Empty,
        user.Email ?? string.Empty,
        user.FullName,
        user.Department,
        user.JobTitle,
        role,
        user.IsActive,
        user.CreatedAt,
        user.LastLoginAt,
        user.LockoutEnd is { } end && end > DateTimeOffset.UtcNow,
        user.LockoutEnd,
        user.AccessFailedCount);

    public static DocumentDto ToDto(Document document, bool includeContent) => new(
        document.Id,
        document.Title,
        document.Description,
        document.Classification,
        includeContent ? document.Content : null,
        document.HasFile,
        document.OriginalFileName,
        document.ContentType,
        document.SizeBytes,
        document.OwnerId,
        document.Owner?.FullName,
        document.CreatedAt,
        document.UpdatedAt);

    public static AuditEventDto ToDto(AuditEvent e) => new(
        e.Id,
        e.Timestamp,
        e.EventType,
        e.Action,
        e.Success,
        e.Severity,
        e.UserId,
        e.Username,
        e.SourceIp,
        e.UserAgent,
        e.HttpMethod,
        e.Endpoint,
        e.Resource,
        e.Details,
        e.RequestId);
}
