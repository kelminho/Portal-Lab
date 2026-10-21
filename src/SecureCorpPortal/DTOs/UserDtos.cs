using System.ComponentModel.DataAnnotations;

namespace SecureCorpPortal.DTOs;

/// <summary>
/// Representação pública de um usuário. Nunca expõe PasswordHash, SecurityStamp
/// ou outros campos internos do Identity — por isso não retornamos a entidade.
/// </summary>
public sealed record UserDto(
    int Id,
    string UserName,
    string Email,
    string FullName,
    string? Department,
    string? JobTitle,
    string Role,
    bool IsActive,
    DateTime CreatedAt,
    DateTime? LastLoginAt);

/// <summary>Visão administrativa: inclui dados de bloqueio de conta.</summary>
public sealed record AdminUserDto(
    int Id,
    string UserName,
    string Email,
    string FullName,
    string? Department,
    string? JobTitle,
    string Role,
    bool IsActive,
    DateTime CreatedAt,
    DateTime? LastLoginAt,
    bool IsLockedOut,
    DateTimeOffset? LockoutEnd,
    int AccessFailedCount);

/// <summary>
/// Atualização parcial de usuário (PUT /api/users/{id}). Campos nulos não são alterados.
/// Role e IsActive só podem ser enviados por ADMIN; o service rejeita (403) caso contrário.
/// Usar um DTO explícito — em vez de receber a entidade — impede "mass assignment".
/// </summary>
public sealed class UpdateUserRequest
{
    [StringLength(100, MinimumLength = 1)]
    public string? FullName { get; set; }

    [EmailAddress]
    [StringLength(256)]
    public string? Email { get; set; }

    [StringLength(100)]
    public string? Department { get; set; }

    [StringLength(100)]
    public string? JobTitle { get; set; }

    [StringLength(20)]
    public string? Role { get; set; }

    public bool? IsActive { get; set; }
}
