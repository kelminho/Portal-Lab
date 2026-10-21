using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureCorpPortal.DTOs;
using SecureCorpPortal.Services;

namespace SecureCorpPortal.Controllers.Api;

/// <summary>GET /api/dashboard — conteúdo varia conforme o papel do usuário.</summary>
[Authorize]
[Route("api/dashboard")]
public class DashboardApiController : ApiControllerBase
{
    private readonly IDashboardService _dashboard;

    public DashboardApiController(IDashboardService dashboard)
    {
        _dashboard = dashboard;
    }

    [HttpGet("")]
    [ProducesResponseType(typeof(DashboardDto), StatusCodes.Status200OK)]
    public async Task<ActionResult<DashboardDto>> Get(CancellationToken cancellationToken) =>
        Ok(await _dashboard.GetAsync(CurrentUser, cancellationToken));
}
