using Microsoft.EntityFrameworkCore;
using SecureCorpPortal.Data;
using SecureCorpPortal.DTOs;
using SecureCorpPortal.Models;

namespace SecureCorpPortal.Repositories;

public sealed class AuditEventRepository : IAuditEventRepository
{
    private readonly AppDbContext _db;

    public AuditEventRepository(AppDbContext db)
    {
        _db = db;
    }

    public async Task AddAsync(AuditEvent auditEvent, CancellationToken cancellationToken = default)
    {
        _db.AuditEvents.Add(auditEvent);
        await _db.SaveChangesAsync(cancellationToken);
    }

    public async Task<(IReadOnlyList<AuditEvent> Items, int TotalCount)> QueryAsync(
        AuditQuery query, CancellationToken cancellationToken = default)
    {
        IQueryable<AuditEvent> events = _db.AuditEvents.AsNoTracking();

        if (query.EventType is { } eventType)
        {
            events = events.Where(e => e.EventType == eventType);
        }

        if (query.Severity is { } severity)
        {
            events = events.Where(e => e.Severity == severity);
        }

        if (!string.IsNullOrWhiteSpace(query.Username))
        {
            var username = query.Username.Trim().ToLower();
            events = events.Where(e => e.Username != null && e.Username.ToLower().Contains(username));
        }

        if (query.Success is { } success)
        {
            events = events.Where(e => e.Success == success);
        }

        if (query.From is { } from)
        {
            var fromUtc = AsUtc(from);
            events = events.Where(e => e.Timestamp >= fromUtc);
        }

        if (query.To is { } to)
        {
            var toUtc = AsUtc(to);
            events = events.Where(e => e.Timestamp <= toUtc);
        }

        var total = await events.CountAsync(cancellationToken);
        var items = await events
            .OrderByDescending(e => e.Timestamp)
            .ThenByDescending(e => e.Id)
            .Skip((query.Page - 1) * query.PageSize)
            .Take(query.PageSize)
            .ToListAsync(cancellationToken);

        return (items, total);
    }

    public Task<int> CountSinceAsync(AuditEventType eventType, DateTime sinceUtc, CancellationToken cancellationToken = default) =>
        _db.AuditEvents.CountAsync(e => e.EventType == eventType && e.Timestamp >= sinceUtc, cancellationToken);

    public async Task<IReadOnlyList<AuditEvent>> GetRecentAsync(
        int take, int? userId = null, CancellationToken cancellationToken = default)
    {
        var events = _db.AuditEvents.AsNoTracking();
        if (userId is not null)
        {
            events = events.Where(e => e.UserId == userId);
        }

        return await events
            .OrderByDescending(e => e.Timestamp)
            .ThenByDescending(e => e.Id)
            .Take(take)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// O PostgreSQL (timestamptz) exige DateTime com Kind=Utc. Datas vindas de
    /// formulários chegam como "Unspecified" e são tratadas como UTC.
    /// </summary>
    private static DateTime AsUtc(DateTime value) => value.Kind switch
    {
        DateTimeKind.Utc => value,
        DateTimeKind.Local => value.ToUniversalTime(),
        _ => DateTime.SpecifyKind(value, DateTimeKind.Utc)
    };
}
