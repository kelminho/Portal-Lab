namespace SecureCorpPortal.Logging;

/// <summary>
/// Defesa em profundidade: mesmo que algum código registre por engano uma
/// propriedade chamada "password" ou "token", o formatter substitui o valor.
/// A regra principal continua sendo: NUNCA passe segredos para o logger.
/// </summary>
public static class SensitiveData
{
    public const string Mask = "[REDACTED]";

    private static readonly string[] SensitiveMarkers =
    [
        "password", "passwd", "pwd", "secret", "token", "apikey", "api_key",
        "authorization", "cookie", "credential", "connectionstring",
        "connection_string", "privatekey", "private_key", "securitystamp"
    ];

    public static bool IsSensitiveKey(string? key)
    {
        if (string.IsNullOrEmpty(key))
        {
            return false;
        }

        var normalized = key.ToLowerInvariant();
        return SensitiveMarkers.Any(normalized.Contains);
    }
}

/// <summary>
/// Prepara a query string da requisição para o log: mantém o texto bruto (codificado),
/// que é o que as detecções de SQLi/XSS/path traversal precisam analisar, mas mascara
/// o valor de parâmetros com nome sensível (ex.: "token", "password").
/// </summary>
public static class QueryStringLogFormatter
{
    public const int MaxLength = 2048;

    public static string? Format(string? queryString)
    {
        if (string.IsNullOrEmpty(queryString))
        {
            return null;
        }

        var pairs = queryString.TrimStart('?')
            .Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(MaskIfSensitive);

        return LogSanitizer.Clean(string.Join('&', pairs), MaxLength);
    }

    private static string MaskIfSensitive(string pair)
    {
        var separator = pair.IndexOf('=');
        if (separator < 0)
        {
            return pair;
        }

        var key = pair[..separator];
        return SensitiveData.IsSensitiveKey(SafeUnescape(key))
            ? $"{key}={SensitiveData.Mask}"
            : pair;
    }

    private static string SafeUnescape(string value)
    {
        try
        {
            return Uri.UnescapeDataString(value);
        }
        catch (UriFormatException)
        {
            return value;
        }
    }
}

/// <summary>Limpeza de valores vindos do usuário antes de irem para log/auditoria.</summary>
public static class LogSanitizer
{
    /// <summary>
    /// Remove caracteres de controle (ex.: \r\n, que permitiriam forjar linhas de log)
    /// e limita o tamanho do texto.
    /// </summary>
    public static string? Clean(string? value, int maxLength)
    {
        if (value is null)
        {
            return null;
        }

        var cleaned = new string(value.Where(c => !char.IsControl(c)).ToArray()).Trim();
        if (cleaned.Length == 0)
        {
            return null;
        }

        return cleaned.Length <= maxLength ? cleaned : cleaned[..maxLength];
    }
}
