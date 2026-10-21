using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using SecureCorpPortal.Models.ViewModels;

namespace SecureCorpPortal.Controllers;

/// <summary>
/// Páginas de erro. Não possui atributo de verbo HTTP porque é re-executado com o
/// método original da requisição (GET, POST...). Por isso também ignora antiforgery.
/// </summary>
[AllowAnonymous]
[IgnoreAntiforgeryToken]
[ApiExplorerSettings(IgnoreApi = true)]
public class ErrorController : Controller
{
    /// <summary>Destino do UseExceptionHandler (exceções não tratadas em páginas MVC).</summary>
    [Route("/error")]
    public IActionResult Error() =>
        View("Error", new ErrorViewModel { StatusCode = 500, RequestId = HttpContext.TraceIdentifier });

    /// <summary>Destino do UseStatusCodePagesWithReExecute (403, 404...).</summary>
    [Route("/error/{statusCode:int}")]
    public IActionResult Status(int statusCode)
    {
        var feature = HttpContext.Features.Get<IStatusCodeReExecuteFeature>();
        if (feature?.OriginalPath.StartsWith("/api", StringComparison.OrdinalIgnoreCase) == true)
        {
            return Problem(statusCode: statusCode);
        }

        Response.StatusCode = statusCode;
        return View("Error", new ErrorViewModel { StatusCode = statusCode, RequestId = HttpContext.TraceIdentifier });
    }
}
