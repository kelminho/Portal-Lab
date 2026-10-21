namespace SecureCorpPortal.Extensions;

public static class HttpContextExtensions
{
    /// <summary>
    /// IP de origem da conexão. Endereços IPv4 mapeados em IPv6 ("::ffff:10.0.0.1")
    /// são convertidos para IPv4 para facilitar correlação no SIEM.
    /// Observação: atrás de um proxy reverso seria necessário configurar
    /// ForwardedHeaders (ver docs/security/extension-points.md).
    /// </summary>
    public static string? GetSourceIp(this HttpContext context)
    {
        var address = context.Connection.RemoteIpAddress;
        if (address is null)
        {
            return null;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        return address.ToString();
    }

    public static bool IsApiRequest(this HttpRequest request) =>
        request.Path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase);
}
