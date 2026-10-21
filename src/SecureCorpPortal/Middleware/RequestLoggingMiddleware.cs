using System.Diagnostics;
using Microsoft.AspNetCore.Diagnostics;
using SecureCorpPortal.Extensions;
using SecureCorpPortal.Logging;
using Serilog.Context;

namespace SecureCorpPortal.Middleware;

/// <summary>
/// Registra UM evento "HttpRequest" por requisição, com status_code e duration_ms.
/// Fica depois de UseAuthentication para já conhecer o usuário (user_id/username).
/// Arquivos estáticos não passam por aqui (são atendidos antes), o que reduz ruído.
/// </summary>
public sealed class RequestLoggingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RequestLoggingMiddleware> _logger;

    public RequestLoggingMiddleware(RequestDelegate next, ILogger<RequestLoggingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Re-execuções internas (páginas de erro) não geram uma segunda linha de log.
        if (context.Features.Get<IStatusCodeReExecuteFeature>() is not null ||
            context.Features.Get<IExceptionHandlerFeature>() is not null)
        {
            await _next(context);
            return;
        }

        var isAuthenticated = context.User.Identity?.IsAuthenticated == true;
        using var userIdProperty = isAuthenticated
            ? LogContext.PushProperty(LogFields.UserId, context.User.GetUserId())
            : null;
        using var usernameProperty = isAuthenticated
            ? LogContext.PushProperty(LogFields.Username, context.User.Identity!.Name)
            : null;

        var start = Stopwatch.GetTimestamp();
        var statusCode = StatusCodes.Status500InternalServerError;
        try
        {
            await _next(context);
            statusCode = context.Response.StatusCode;
        }
        finally
        {
            var elapsedMs = Math.Round(Stopwatch.GetElapsedTime(start).TotalMilliseconds, 2);
            var level = statusCode switch
            {
                >= 500 => LogLevel.Error,
                401 or 403 => LogLevel.Warning,
                _ => LogLevel.Information
            };

            using (_logger.BeginEventScope(TechnicalEventTypes.HttpRequest, EventCategories.Http, action: "http.request"))
            {
                _logger.Log(level, "HTTP {http_method} {endpoint} respondeu {status_code} em {duration_ms} ms",
                    context.Request.Method, context.Request.Path.Value, statusCode, elapsedMs);
            }
        }
    }
}
