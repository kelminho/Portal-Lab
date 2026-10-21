using SecureCorpPortal.Configuration;

namespace SecureCorpPortal.Services;

/// <summary>
/// Usuário autenticado que está executando a operação (derivado das claims do cookie).
/// Os services recebem este objeto em vez de depender de HttpContext diretamente,
/// o que torna as regras de autorização explícitas e fáceis de testar.
/// </summary>
public sealed record CurrentUser(int Id, string UserName, string Role)
{
    public bool IsAdmin => Role == AppRoles.Admin;

    public bool IsAnalyst => Role == AppRoles.Analyst;

    public bool IsGuest => Role == AppRoles.Guest;
}
