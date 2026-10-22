using System.Text.RegularExpressions;
using SecureCorpPortal.Extensions;
using SecureCorpPortal.Logging;
using Serilog.Context;

namespace SecureCorpPortal.Middleware;

/// <summary>
/// Primeiro middleware do pipeline. Para cada requisição:
/// 1. define o request_id (reaproveita X-Request-ID se válido, senão gera um novo);
/// 2. devolve o request_id no header de resposta X-Request-ID;
/// 3. adiciona ao contexto de log os campos request_id, source_ip, http_method,
///    endpoint, query_string (parâmetros sensíveis mascarados) e user_agent — assim TODO log da requisição carrega esses campos.
/// </summary>
public sealed partial class CorrelationMiddleware
{
    public const string RequestIdHeader = "X-Request-ID";

    private readonly RequestDelegate _next;

    public CorrelationMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var requestId = ResolveRequestId(context.Request.Headers[RequestIdHeader].ToString());
        context.TraceIdentifier = requestId;

        context.Response.OnStarting(() =>
        {
            context.Response.Headers[RequestIdHeader] = requestId;
            return Task.CompletedTask;
        });

        using (LogContext.PushProperty(LogFields.RequestId, requestId))
        using (LogContext.PushProperty(LogFields.SourceIp, context.GetSourceIp()))
        using (LogContext.PushProperty(LogFields.HttpMethod, context.Request.Method))
        using (LogContext.PushProperty(LogFields.Endpoint, context.Request.Path.Value ?? "/"))
        using (LogContext.PushProperty(LogFields.QueryString,
                   QueryStringLogFormatter.Format(context.Request.QueryString.Value)))
        using (LogContext.PushProperty(LogFields.UserAgent,
                   LogSanitizer.Clean(context.Request.Headers.UserAgent.ToString(), 512)))
        {
            await _next(context);
        }
    }

    /// <summary>
    /// Aceita o request_id enviado pelo cliente/proxy apenas se tiver formato seguro
    /// (evita injeção de conteúdo arbitrário nos logs).
    /// </summary>
    internal static string ResolveRequestId(string? incoming) =>
        !string.IsNullOrEmpty(incoming) && ValidRequestId().IsMatch(incoming)
            ? incoming
            : Guid.NewGuid().ToString("N");

    [GeneratedRegex("^[A-Za-z0-9._-]{8,64}$")]
    private static partial Regex ValidRequestId();
}
