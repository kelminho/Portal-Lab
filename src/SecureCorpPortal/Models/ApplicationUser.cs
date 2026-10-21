using Microsoft.AspNetCore.Identity;

namespace SecureCorpPortal.Models;

/// <summary>
/// Entidade "User" da aplicação. Estende o IdentityUser (que já possui
/// UserName, Email, PasswordHash, SecurityStamp, LockoutEnd, AccessFailedCount...)
/// com dados corporativos. Chave primária inteira (int) para facilitar o estudo.
/// Tabela: users.
/// </summary>
public class ApplicationUser : IdentityUser<int>
{
    public string FullName { get; set; } = string.Empty;

    public string? Department { get; set; }

    public string? JobTitle { get; set; }

    /// <summary>Usuários inativos não conseguem autenticar.</summary>
    public bool IsActive { get; set; } = true;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime? LastLoginAt { get; set; }

    /// <summary>Documentos dos quais o usuário é dono (1:N).</summary>
    public ICollection<Document> Documents { get; set; } = new List<Document>();
}
