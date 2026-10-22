using SecureCorpPortal.Configuration;

namespace SecureCorpPortal.Data;

/// <summary>
/// Contas de demonstração criadas pelo seed (somente quando Seed:Enabled=true).
///
/// ATENÇÃO: credenciais fixas e públicas, destinadas EXCLUSIVAMENTE ao ambiente
/// de laboratório local. Nunca habilite o seed em um ambiente real.
/// </summary>
public static class DemoAccounts
{
    public sealed record DemoAccount(
        string UserName,
        string Password,
        string Role,
        string FullName,
        string Email,
        string Department,
        string JobTitle);

    public static readonly DemoAccount Admin = new(
        "admin", "Admin@123!", AppRoles.Admin,
        "Carla Mendes", "admin@securecorp.local",
        "Tecnologia da Informação", "Administradora de Sistemas");

    public static readonly DemoAccount Analyst = new(
        "analyst", "Analyst@123!", AppRoles.Analyst,
        "Rafael Souza", "analyst@securecorp.local",
        "Segurança da Informação", "Analista de Segurança");

    public static readonly DemoAccount Employee = new(
        "employee", "Employee@123!", AppRoles.Employee,
        "Juliana Lima", "employee@securecorp.local",
        "Financeiro", "Assistente Financeira");

    public static readonly DemoAccount Guest = new(
        "guest", "Guest@123!", AppRoles.Guest,
        "Pedro Alves", "guest@securecorp.local",
        "Parceiros Externos", "Consultor Convidado");

    public static readonly DemoAccount Sales = new(
        "marcos.oliveira", "Employee@123!", AppRoles.Employee,
        "Marcos Oliveira", "marcos.oliveira@securecorp.local",
        "Comercial", "Executivo de Contas");

    public static readonly DemoAccount HumanResources = new(
        "patricia.santos", "Employee@123!", AppRoles.Employee,
        "Patrícia Santos", "patricia.santos@securecorp.local",
        "Recursos Humanos", "Analista de RH");

    public static readonly IReadOnlyList<DemoAccount> All =
        [Admin, Analyst, Employee, Guest, Sales, HumanResources];

    public static DemoAccount ByUserName(string userName) =>
        All.First(a => a.UserName == userName);
}
