using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using SecureCorpPortal.Extensions;
using SecureCorpPortal.Logging;
using SecureCorpPortal.Middleware;
using SecureCorpPortal.Models;
using SecureCorpPortal.Services;

namespace SecureCorpPortal.Configuration;

/// <summary>
/// Personaliza o comportamento do cookie de autenticação:
/// - páginas MVC são redirecionadas para /login ou /access-denied;
/// - chamadas /api/* recebem 401/403 em JSON (sem redirect);
/// - toda negação por policy/papel gera um evento de auditoria AccessDenied.
/// </summary>
public static class AuthenticationEventHandlers
{
    public static async Task OnRedirectToLogin(RedirectContext<CookieAuthenticationOptions> context)
    {
        var logger = context.HttpContext.RequestServices
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger("SecureCorpPortal.Security.Authentication");

        using (logger.BeginEventScope(TechnicalEventTypes.AuthenticationRequired, EventCategories.Security,
                   action: "authentication.challenge"))
        {
            logger.LogInformation("Acesso a recurso protegido sem autenticação: {endpoint}",
                context.Request.Path.Value);
        }

        if (context.Request.IsApiRequest())
        {
            await ProblemResponses.WriteAsync(context.HttpContext, StatusCodes.Status401Unauthorized,
                "Autenticação necessária.");
            return;
        }

        context.Response.Redirect(context.RedirectUri);
    }

    public static async Task OnRedirectToAccessDenied(RedirectContext<CookieAuthenticationOptions> context)
    {
        var audit = context.HttpContext.RequestServices.GetRequiredService<IAuditService>();
        await audit.RecordAsync(new AuditEntry(AuditEventType.AccessDenied, "authorization.policy_denied", Success: false)
        {
            Resource = context.Request.Path.Value,
            Details = "Usuário autenticado sem o papel/policy exigido pelo endpoint."
        });

        if (context.Request.IsApiRequest())
        {
            await ProblemResponses.WriteAsync(context.HttpContext, StatusCodes.Status403Forbidden,
                "Acesso negado.", "Seu papel não permite acessar este recurso.");
            return;
        }

        context.Response.Redirect(context.RedirectUri);
    }
}
