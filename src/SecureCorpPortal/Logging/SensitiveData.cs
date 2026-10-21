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
