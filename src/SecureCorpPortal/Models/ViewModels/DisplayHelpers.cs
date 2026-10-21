using System.Globalization;

namespace SecureCorpPortal.Models.ViewModels;

/// <summary>Formatação usada pelas Razor Views (rótulos em português e classes CSS).</summary>
public static class DisplayHelpers
{
    public static string ClassificationLabel(DocumentClassification classification) => classification switch
    {
        DocumentClassification.Public => "Público",
        DocumentClassification.Internal => "Interno",
        DocumentClassification.Confidential => "Confidencial",
        DocumentClassification.Restricted => "Restrito",
        _ => classification.ToString()
    };

    public static string ClassificationLabel(string classification) =>
        Enum.TryParse<DocumentClassification>(classification, out var parsed)
            ? ClassificationLabel(parsed)
            : classification;

    public static string ClassificationCss(DocumentClassification classification) =>
        "badge badge-" + classification.ToString().ToLowerInvariant();

    public static string RoleCss(string role) => "badge role-" + role.ToLowerInvariant();

    public static string SeverityCss(AuditSeverity severity) => "badge sev-" + severity.ToString().ToLowerInvariant();

    public static string FormatDate(DateTime? value) =>
        value is null ? "—" : value.Value.ToString("dd/MM/yyyy HH:mm", CultureInfo.InvariantCulture) + " UTC";

    public static string FormatBytes(long? bytes)
    {
        if (bytes is null)
        {
            return "—";
        }

        string[] units = ["B", "KB", "MB", "GB"];
        double size = bytes.Value;
        var unit = 0;
        while (size >= 1024 && unit < units.Length - 1)
        {
            size /= 1024;
            unit++;
        }

        return $"{size.ToString("0.#", CultureInfo.InvariantCulture)} {units[unit]}";
    }
}
