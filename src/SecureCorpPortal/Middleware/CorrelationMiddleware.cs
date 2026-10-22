using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using SecureCorpPortal.Configuration;
using SecureCorpPortal.Extensions;
using SecureCorpPortal.Logging;
using Serilog.Context;

namespace SecureCorpPortal.Middleware;

/// <summary>
/// Primeiro middleware do pipeline. Para cada requisição:
/// 1. define o request_id (reaproveita X-Request-ID se válido, senão gera um novo);
/// 2. devolve o request_id no header de resposta X-Request-ID;
/// 3. adiciona ao contexto de log os campos request_id, source_ip, http_method,
///    endpoint, query_string (parâmetros sensíveis mascarados) e user_agent — assim TODO log da requisição carrega esses campos;
/// 4. adiciona session_ref (hash truncado do cookie de sessão), origin, referer (sem query), sec_fetch_site
///    e content_length, usados para correlacionar sessões e detectar CSRF/uploads anômalos.
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
        var incomingRequestId = context.Request.Headers[RequestIdHeader].ToString();
        var requestId = ResolveRequestId(incomingRequestId);
        context.TraceIdentifier = requestId;

        context.Response.OnStarting(() =>
        {
            context.Response.Headers[RequestIdHeader] = requestId;
            return Task.CompletedTask;
        });

        // Valor enviado pelo cliente e descartado (formato inválido): fica no log, já limpo e truncado,
        // para detectar tentativas de forjar/injetar request_id. Só existe quando houve rejeição.
        using var rejectedRequestId = !string.IsNullOrEmpty(incomingRequestId) && requestId != incomingRequestId
            ? LogContext.PushProperty("request_id_rejected", LogSanitizer.Clean(incomingRequestId, 64))
            : null;

        using (LogContext.PushProperty(LogFields.RequestId, requestId))
        using (LogContext.PushProperty(LogFields.SourceIp, context.GetSourceIp()))
        using (LogContext.PushProperty(LogFields.SourcePort, context.Connection.RemotePort))
        using (LogContext.PushProperty(LogFields.HttpMethod, context.Request.Method))
        using (LogContext.PushProperty(LogFields.Endpoint, context.Request.Path.Value ?? "/"))
        using (LogContext.PushProperty(LogFields.QueryString,
                   QueryStringLogFormatter.Format(context.Request.QueryString.Value)))
        using (LogContext.PushProperty(LogFields.UserAgent,
                   LogSanitizer.Clean(context.Request.Headers.UserAgent.ToString(), 512)))
        using (LogContext.PushProperty(LogFields.SessionRef, SessionReference(context.Request)))
        using (LogContext.PushProperty(LogFields.Origin,
                   LogSanitizer.Clean(context.Request.Headers.Origin.ToString(), 256)))
        using (LogContext.PushProperty(LogFields.Referer, RefererWithoutQuery(context.Request.Headers.Referer.ToString())))
        using (LogContext.PushProperty(LogFields.SecFetchSite,
                   LogSanitizer.Clean(context.Request.Headers["Sec-Fetch-Site"].ToString(), 32)))
        using (LogContext.PushProperty(LogFields.ContentLength, context.Request.ContentLength))
        {
            await _next(context);
        }
    }

    /// <summary>
    /// Referência opaca da sessão: primeiros 16 hex do SHA-256 do cookie de autenticação.
    /// Permite correlacionar login → requisições → logout (e o reuso de um cookie após o logout)
    /// sem gravar o cookie, que é a credencial da sessão. Não é reversível para o cookie.
    /// </summary>
    internal static string? SessionReference(HttpRequest request)
    {
        if (!request.Cookies.TryGetValue(PortalCookies.Auth, out var cookie) || string.IsNullOrEmpty(cookie))
        {
            return null;
        }

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(cookie)))[..16].ToLowerInvariant();
    }

    /// <summary>Referer sem query string nem fragmento (podem carregar tokens); o restante é mantido.</summary>
    internal static string? RefererWithoutQuery(string? referer)
    {
        if (string.IsNullOrWhiteSpace(referer))
        {
            return null;
        }

        return Uri.TryCreate(referer, UriKind.Absolute, out var uri)
            ? LogSanitizer.Clean(uri.GetLeftPart(UriPartial.Path), 256)
            : LogSanitizer.Clean(referer.Split('?', '#')[0], 256);
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
