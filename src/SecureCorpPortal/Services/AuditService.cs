using SecureCorpPortal.DTOs;
using SecureCorpPortal.Extensions;
using SecureCorpPortal.Logging;
using SecureCorpPortal.Models;
using SecureCorpPortal.Repositories;

namespace SecureCorpPortal.Services;

/// <summary>
/// Camada de auditoria. Cada evento é:
/// 1. persistido na tabela audit_events (consultável em /admin/logs);
/// 2. emitido no log JSON com event_category = "audit" (vai para logs/security-*.json).
///
/// A gravação usa um DbContext separado (novo escopo de DI). Assim o evento de
/// auditoria não é afetado — nem "carrega junto" — alterações pendentes da
/// operação de negócio que está em andamento.
///
/// LAB-EXTENSION-POINT (logging/detection): ver docs/security/extension-points.md.
/// </summary>
public sealed class AuditService : IAuditService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IAuditEventRepository _repository;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<AuditService> _logger;

    public AuditService(
        IServiceScopeFactory scopeFactory,
        IAuditEventRepository repository,
        IHttpContextAccessor httpContextAccessor,
        ILogger<AuditService> logger)
    {
        _scopeFactory = scopeFactory;
        _repository = repository;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    public async Task RecordAsync(AuditEntry entry, CancellationToken cancellationToken = default)
    {
        var http = _httpContextAccessor.HttpContext;
        var principal = http?.User;
        var isAuthenticated = principal?.Identity?.IsAuthenticated == true;

        var auditEvent = new AuditEvent
        {
            Timestamp = DateTime.UtcNow,
            EventType = entry.EventType,
            Action = LogSanitizer.Clean(entry.Action, 100) ?? entry.EventType.ToString(),
            Success = entry.Success,
            Severity = entry.Severity ?? AuditSeverityDefaults.For(entry.EventType, entry.Success),
            UserId = entry.UserId ?? (isAuthenticated ? principal!.GetUserId() : null),
            Username = LogSanitizer.Clean(entry.Username ?? (isAuthenticated ? principal!.Identity!.Name : null), 256),
            SourceIp = http?.GetSourceIp(),
            UserAgent = LogSanitizer.Clean(http?.Request.Headers.UserAgent.ToString(), 512),
            HttpMethod = http?.Request.Method,
            Endpoint = LogSanitizer.Clean(http?.Request.Path.Value, 512),
            Resource = LogSanitizer.Clean(entry.Resource, 256),
            Details = LogSanitizer.Clean(entry.Details, 2000),
            RequestId = http?.TraceIdentifier
        };

        try
        {
            using var scope = _scopeFactory.CreateScope();
            var repository = scope.ServiceProvider.GetRequiredService<IAuditEventRepository>();
            await repository.AddAsync(auditEvent, cancellationToken);
        }
        catch (Exception ex)
        {
            // Falha ao gravar auditoria não derruba a requisição, mas fica registrada com severidade alta.
            using (_logger.BeginEventScope(TechnicalEventTypes.AuditPersistenceFailed, EventCategories.Security, severity: "high"))
            {
                _logger.LogError(ex, "Falha ao persistir evento de auditoria {audit_event_type}", entry.EventType.ToString());
            }
        }

        WriteToLog(auditEvent);
    }

    public async Task<PagedResult<AuditEventDto>> QueryAsync(AuditQuery query, CancellationToken cancellationToken = default)
    {
        query.Page = Math.Max(1, query.Page);
        query.PageSize = Math.Clamp(query.PageSize, 1, 200);

        var (items, total) = await _repository.QueryAsync(query, cancellationToken);
        return new PagedResult<AuditEventDto>(items.Select(DtoMapper.ToDto).ToList(), query.Page, query.PageSize, total);
    }

    public async Task<IReadOnlyList<AuditEventDto>> GetRecentAsync(
        int take, int? userId = null, CancellationToken cancellationToken = default)
    {
        var items = await _repository.GetRecentAsync(take, userId, cancellationToken);
        return items.Select(DtoMapper.ToDto).ToList();
    }

    private void WriteToLog(AuditEvent auditEvent)
    {
        var level = auditEvent.Severity switch
        {
            AuditSeverity.Critical => LogLevel.Error,
            AuditSeverity.High or AuditSeverity.Medium => LogLevel.Warning,
            _ => LogLevel.Information
        };

        var outcome = auditEvent.Success ? "success" : "failure";

        var state = new Dictionary<string, object?>
        {
            [LogFields.EventCategory] = EventCategories.Audit,
            [LogFields.Severity] = auditEvent.Severity.ToString().ToLowerInvariant(),
            ["audit_id"] = auditEvent.Id
        };

        // Campos do "ator" do evento (sobrepõem os do contexto da requisição).
        if (auditEvent.UserId is not null)
        {
            state[LogFields.UserId] = auditEvent.UserId;
        }

        if (auditEvent.Username is not null)
        {
            state[LogFields.Username] = auditEvent.Username;
        }

        if (auditEvent.Resource is not null)
        {
            state[LogFields.Resource] = auditEvent.Resource;
        }

        if (auditEvent.Details is not null)
        {
            state["details"] = auditEvent.Details;
        }

        using (_logger.BeginScope(state))
        {
            _logger.Log(level, "Audit {event_type}: {action} [{outcome}]",
                auditEvent.EventType.ToString(), auditEvent.Action, outcome);
        }
    }
}
