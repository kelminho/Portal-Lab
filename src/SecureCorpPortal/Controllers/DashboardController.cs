using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureCorpPortal.Services;

namespace SecureCorpPortal.Controllers;

[Authorize]
public class DashboardController : PortalControllerBase
{
    private readonly IDashboardService _dashboard;

    public DashboardController(IDashboardService dashboard)
    {
        _dashboard = dashboard;
    }

    [HttpGet("/dashboard")]
    public async Task<IActionResult> Index(CancellationToken cancellationToken) =>
        View(await _dashboard.GetAsync(CurrentUser, cancellationToken));
}
