using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SecureCorpPortal.Controllers;

public class HomeController : PortalControllerBase
{
    /// <summary>Raiz do site: dashboard se autenticado, senão login.</summary>
    [AllowAnonymous]
    [HttpGet("/")]
    public IActionResult Index() =>
        User.Identity?.IsAuthenticated == true
            ? RedirectToAction("Index", "Dashboard")
            : RedirectToAction("Login", "Account");
}
