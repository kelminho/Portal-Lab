using Microsoft.AspNetCore.Identity;

namespace SecureCorpPortal.Models;

/// <summary>
/// Entidade "Role". O relacionamento N:N com usuários é feito pela tabela
/// user_roles (IdentityUserRole&lt;int&gt;). Nesta aplicação cada usuário tem um único papel.
/// Tabela: roles.
/// </summary>
public class ApplicationRole : IdentityRole<int>
{
    public ApplicationRole()
    {
    }

    public ApplicationRole(string roleName, string description) : base(roleName)
    {
        Description = description;
    }

    public string? Description { get; set; }
}
