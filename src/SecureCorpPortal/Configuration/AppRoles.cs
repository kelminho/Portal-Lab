namespace SecureCorpPortal.Configuration;

/// <summary>
/// Papéis (roles) da aplicação. Cada usuário possui exatamente um papel.
/// A matriz completa de permissões está em docs/security/permissions.md.
/// </summary>
public static class AppRoles
{
    public const string Admin = "ADMIN";
    public const string Analyst = "ANALYST";
    public const string Employee = "EMPLOYEE";
    public const string Guest = "GUEST";

    /// <summary>Todos os papéis, do maior para o menor privilégio.</summary>
    public static readonly IReadOnlyList<string> All = [Admin, Analyst, Employee, Guest];

    /// <summary>
    /// Converte um valor informado pelo usuário ("admin", "Admin"...) para o nome
    /// canônico do papel. Retorna null se o papel não existir.
    /// </summary>
    public static string? Normalize(string? role) =>
        All.FirstOrDefault(r => string.Equals(r, role?.Trim(), StringComparison.OrdinalIgnoreCase));

    /// <summary>Papel de maior privilégio da lista (GUEST se vazia).</summary>
    public static string Highest(IEnumerable<string> roles)
    {
        var set = roles.ToHashSet(StringComparer.OrdinalIgnoreCase);
        return All.FirstOrDefault(set.Contains) ?? Guest;
    }

    public static string Describe(string role) => role switch
    {
        Admin => "Administração completa: usuários, documentos, área administrativa e auditoria.",
        Analyst => "Consulta de informações, diretório de usuários e indicadores de segurança.",
        Employee => "Próprio perfil e documentos públicos/internos; pode publicar documentos internos.",
        Guest => "Acesso mínimo: próprio perfil e documentos públicos.",
        _ => "Papel desconhecido."
    };
}
