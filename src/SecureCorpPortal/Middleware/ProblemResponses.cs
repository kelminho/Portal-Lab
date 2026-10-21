using System.Text.Json;
using Microsoft.AspNetCore.Mvc;

namespace SecureCorpPortal.Middleware;

/// <summary>Escreve respostas de erro no formato padrão RFC 7807 (application/problem+json).</summary>
public static class ProblemResponses
{
    public static Task WriteAsync(
        HttpContext context,
        int statusCode,
        string title,
        string? detail = null,
        CancellationToken cancellationToken = default)
    {
        context.Response.StatusCode = statusCode;

        var problem = new ProblemDetails
        {
            Status = statusCode,
            Title = title,
            Detail = detail,
            Instance = context.Request.Path
        };
        problem.Extensions["request_id"] = context.TraceIdentifier;

        return context.Response.WriteAsJsonAsync(problem, (JsonSerializerOptions?)null,
            "application/problem+json", cancellationToken);
    }
}
