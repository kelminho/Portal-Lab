namespace SecureCorpPortal.Configuration;

/// <summary>Configuração do armazenamento de arquivos enviados (seção "Storage").</summary>
public sealed class StorageOptions
{
    public const string SectionName = "Storage";

    public static readonly string[] DefaultAllowedExtensions =
        [".pdf", ".txt", ".md", ".csv", ".png", ".jpg", ".jpeg", ".docx", ".xlsx"];

    /// <summary>
    /// Diretório dos uploads, relativo ao ContentRoot ou absoluto.
    /// Fica FORA de wwwroot para que arquivos nunca sejam servidos diretamente
    /// (todo download passa pelo controller, que verifica permissões).
    /// </summary>
    public string UploadDirectory { get; set; } = "data/uploads";

    public long MaxFileSizeBytes { get; set; } = 5 * 1024 * 1024;

    // Vazio por padrão: o binder de configuração ANEXA itens a arrays já preenchidos.
    public string[] AllowedExtensions { get; set; } = [];

    public IReadOnlyList<string> EffectiveAllowedExtensions =>
        AllowedExtensions.Length > 0
            ? AllowedExtensions.Select(e => e.ToLowerInvariant()).ToArray()
            : DefaultAllowedExtensions;
}

/// <summary>Controle da criação dos dados de demonstração (seção "Seed").</summary>
public sealed class SeedOptions
{
    public const string SectionName = "Seed";

    public bool Enabled { get; set; }
}

/// <summary>Destino e formato dos logs (seção "AppLogging").</summary>
public sealed class AppLoggingOptions
{
    public const string SectionName = "AppLogging";

    /// <summary>Diretório dos arquivos JSON, relativo ao ContentRoot ou absoluto.</summary>
    public string Directory { get; set; } = "logs";

    public int RetainedFileCountLimit { get; set; } = 14;

    /// <summary>"text" (legível) ou "json" (mesmo formato dos arquivos).</summary>
    public string ConsoleFormat { get; set; } = "text";
}

/// <summary>Limites fixos de requisição para upload (aplicados antes do model binding).</summary>
public static class UploadLimits
{
    public const long MaxRequestBytes = 10 * 1024 * 1024;
}
