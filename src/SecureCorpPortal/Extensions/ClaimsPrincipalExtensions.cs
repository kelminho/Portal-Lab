using System.Security.Claims;
using SecureCorpPortal.Configuration;
using SecureCorpPortal.Services;

namespace SecureCorpPortal.Extensions;

public static class ClaimsPrincipalExtensions
{
    public static int? GetUserId(this ClaimsPrincipal principal) =>
        int.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var id) ? id : null;

    /// <summary>Papel de maior privilégio presente nas claims (GUEST se nenhum).</summary>
    public static string GetRole(this ClaimsPrincipal principal) =>
        AppRoles.All.FirstOrDefault(principal.IsInRole) ?? AppRoles.Guest;

    /// <summary>
    /// Converte o usuário autenticado (claims do cookie) em um objeto simples
    /// usado pelos services. Só deve ser chamado em endpoints protegidos.
    /// </summary>
    public static CurrentUser ToCurrentUser(this ClaimsPrincipal principal)
    {
        var id = principal.GetUserId()
                 ?? throw new InvalidOperationException("Usuário não autenticado.");

        return new CurrentUser(id, principal.Identity?.Name ?? string.Empty, principal.GetRole());
    }
}
