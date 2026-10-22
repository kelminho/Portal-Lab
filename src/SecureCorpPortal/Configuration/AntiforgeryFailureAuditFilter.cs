using Microsoft.AspNetCore.Mvc.Core.Infrastructure;
using Microsoft.AspNetCore.Mvc.Filters;
using SecureCorpPortal.Models;
using SecureCorpPortal.Services;

namespace SecureCorpPortal.Configuration;

/// <summary>
/// Registra um evento de auditoria quando um POST de formulário MVC é rejeitado por falta ou
/// invalidez do token anti-CSRF (a resposta continua sendo o 400 padrão do framework).
/// Sem isto, a tentativa só apareceria como um HttpRequest 400 indistinguível de outros erros.
///
/// "Always run": o filtro de antiforgery interrompe o pipeline antes da action, e filtros de
/// resultado comuns não executariam nesse caso.
/// </summary>
public sealed class AntiforgeryFailureAuditFilter : IAsyncAlwaysRunResultFilter
{
    private readonly IAuditService _audit;

    public AntiforgeryFailureAuditFilter(IAuditService audit)
    {
        _audit = audit;
    }

    public async Task OnResultExecutionAsync(ResultExecutingContext context, ResultExecutionDelegate next)
    {
        if (context.Result is IAntiforgeryValidationFailedResult)
        {
            await _audit.RecordAsync(new AuditEntry(AuditEventType.AccessDenied, "csrf.validation_failed", Success: false)
            {
                Resource = context.HttpContext.Request.Path.Value,
                Details = "Token anti-CSRF ausente ou inválido."
            }, context.HttpContext.RequestAborted);
        }

        await next();
    }
}
