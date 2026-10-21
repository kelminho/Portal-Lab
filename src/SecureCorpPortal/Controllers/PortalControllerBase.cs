using Microsoft.AspNetCore.Mvc;
using SecureCorpPortal.Extensions;
using SecureCorpPortal.Services;

namespace SecureCorpPortal.Controllers;

/// <summary>
/// Base dos controllers MVC (páginas Razor).
/// [AutoValidateAntiforgeryToken] exige token anti-CSRF em todo POST/PUT/DELETE de formulário.
/// </summary>
[AutoValidateAntiforgeryToken]
public abstract class PortalControllerBase : Controller
{
    public const string SuccessMessageKey = "SuccessMessage";
    public const string ErrorMessageKey = "ErrorMessage";

    protected CurrentUser CurrentUser => User.ToCurrentUser();

    protected void FlashSuccess(string message) => TempData[SuccessMessageKey] = message;

    protected void FlashError(string message) => TempData[ErrorMessageKey] = message;

    protected void AddErrors(ServiceResult result)
    {
        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error);
        }
    }

    /// <summary>
    /// Converte falhas de negócio em status HTTP. O middleware de status code pages
    /// transforma o status em uma página amigável (/error/{status}).
    /// </summary>
    protected IActionResult FromFailure(ServiceResult result) => result.Status switch
    {
        ServiceStatus.NotFound => StatusCode(StatusCodes.Status404NotFound),
        ServiceStatus.Forbidden => StatusCode(StatusCodes.Status403Forbidden),
        ServiceStatus.Conflict => StatusCode(StatusCodes.Status409Conflict),
        _ => StatusCode(StatusCodes.Status400BadRequest)
    };
}
