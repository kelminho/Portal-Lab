using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureCorpPortal.Configuration;
using SecureCorpPortal.DTOs;
using SecureCorpPortal.Models;
using SecureCorpPortal.Services;

namespace SecureCorpPortal.Controllers.Api;

/// <summary>
/// GET /api/admin/users   usuários com dados de bloqueio (ADMIN)
/// GET /api/admin/logs    eventos de auditoria com filtros e paginação (ADMIN)
/// </summary>
[Authorize(Policy = Policies.AdminOnly)]
[Route("api/admin")]
public class AdminApiController : ApiControllerBase
{
    private readonly IUserService _users;
    private readonly IAuditService _audit;

    public AdminApiController(IUserService users, IAuditService audit)
    {
        _users = users;
        _audit = audit;
    }

    [HttpGet("users")]
    [ProducesResponseType(typeof(IReadOnlyList<AdminUserDto>), StatusCodes.Status200OK)]
    public async Task<ActionResult<IReadOnlyList<AdminUserDto>>> Users(CancellationToken cancellationToken) =>
        Ok(await _users.GetAllForAdminAsync(cancellationToken));

    [HttpGet("logs")]
    [ProducesResponseType(typeof(PagedResult<AuditEventDto>), StatusCodes.Status200OK)]
    public async Task<ActionResult<PagedResult<AuditEventDto>>> Logs([FromQuery] AuditQuery query, CancellationToken cancellationToken)
    {
        await _audit.RecordAsync(new AuditEntry(AuditEventType.AdminAction, "audit_log.viewed")
        {
            Severity = AuditSeverity.Low
        }, cancellationToken);

        return Ok(await _audit.QueryAsync(query, cancellationToken));
    }
}
