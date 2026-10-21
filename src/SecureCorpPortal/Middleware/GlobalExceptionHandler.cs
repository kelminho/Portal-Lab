using Microsoft.AspNetCore.Diagnostics;
using SecureCorpPortal.Extensions;
using SecureCorpPortal.Logging;

namespace SecureCorpPortal.Middleware;

/// <summary>
/// Tratamento centralizado de exceções não tratadas:
/// - registra a exceção completa no log (event_type = ApplicationError);
/// - para /api/* devolve um ProblemDetails genérico com o request_id;
/// - para páginas MVC retorna false e o UseExceptionHandler("/error") renderiza a página de erro.
/// Detalhes internos (stack trace, mensagens de exceção) nunca são enviados ao cliente.
/// </summary>
public sealed class GlobalExceptionHandler : IExceptionHandler
{
    private readonly ILogger<GlobalExceptionHandler> _logger;

    public GlobalExceptionHandler(ILogger<GlobalExceptionHandler> logger)
    {
        _logger = logger;
    }

    public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
    {
        using (_logger.BeginEventScope(TechnicalEventTypes.ApplicationError, EventCategories.Application,
                   severity: "high", action: "application.unhandled_exception"))
        {
            _logger.LogError(exception, "Exceção não tratada ao processar {http_method} {endpoint}",
                httpContext.Request.Method, httpContext.Request.Path.Value);
        }

        if (!httpContext.Request.IsApiRequest())
        {
            return false;
        }

        await ProblemResponses.WriteAsync(httpContext, StatusCodes.Status500InternalServerError,
            "Erro interno.", "Ocorreu um erro inesperado. Informe o request_id ao suporte.", cancellationToken);
        return true;
    }
}
