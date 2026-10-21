using Microsoft.AspNetCore.Mvc;
using SecureCorpPortal.Extensions;
using SecureCorpPortal.Services;

namespace SecureCorpPortal.Controllers.Api;

/// <summary>
/// Base dos controllers REST.
/// - [ApiController]: validação automática do modelo (400 com ProblemDetails).
/// - Autenticação pelo mesmo cookie das páginas (SameSite=Strict mitiga CSRF;
///   endpoints JSON exigem Content-Type application/json, o que um formulário
///   HTML de outro site não consegue enviar).
/// </summary>
[ApiController]
[Produces("application/json")]
public abstract class ApiControllerBase : ControllerBase
{
    protected CurrentUser CurrentUser => User.ToCurrentUser();

    /// <summary>Traduz falhas de negócio em respostas HTTP padronizadas.</summary>
    protected ActionResult Failure(ServiceResult result)
    {
        var detail = result.Errors.Count > 0 ? string.Join(" ", result.Errors) : null;

        return result.Status switch
        {
            ServiceStatus.NotFound => Problem(statusCode: StatusCodes.Status404NotFound, title: "Recurso não encontrado.", detail: detail),
            ServiceStatus.Forbidden => Problem(statusCode: StatusCodes.Status403Forbidden, title: "Acesso negado.", detail: detail),
            ServiceStatus.Conflict => Problem(statusCode: StatusCodes.Status409Conflict, title: "Conflito.", detail: detail),
            _ => BadRequest(new ValidationProblemDetails(new Dictionary<string, string[]>
            {
                ["request"] = result.Errors.ToArray()
            })
            {
                Status = StatusCodes.Status400BadRequest,
                Title = "Requisição inválida."
            })
        };
    }
}
