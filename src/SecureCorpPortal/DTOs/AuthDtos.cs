using System.ComponentModel.DataAnnotations;

namespace SecureCorpPortal.DTOs;

public sealed class LoginRequest
{
    [Required(ErrorMessage = "Informe o usuário.")]
    [StringLength(64)]
    public string UserName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Informe a senha.")]
    [StringLength(128)]
    public string Password { get; set; } = string.Empty;
}

/// <summary>
/// Cadastro público. Usado pela API (JSON) e pela página /register (formulário).
/// Repare que NÃO existe campo "Role": todo cadastro público recebe o papel GUEST.
/// Aceitar o papel do cliente permitiria que qualquer um se tornasse ADMIN.
/// </summary>
public sealed class RegisterRequest
{
    [Required(ErrorMessage = "Informe o nome de usuário.")]
    [StringLength(32, MinimumLength = 3, ErrorMessage = "O usuário deve ter entre 3 e 32 caracteres.")]
    [RegularExpression("^[a-zA-Z0-9._-]+$", ErrorMessage = "Use apenas letras, números, ponto, hífen ou sublinhado.")]
    [Display(Name = "Usuário")]
    public string UserName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Informe o e-mail.")]
    [EmailAddress(ErrorMessage = "E-mail inválido.")]
    [StringLength(256)]
    [Display(Name = "E-mail")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Informe o nome completo.")]
    [StringLength(100)]
    [Display(Name = "Nome completo")]
    public string FullName { get; set; } = string.Empty;

    [StringLength(100)]
    [Display(Name = "Departamento")]
    public string? Department { get; set; }

    [Required(ErrorMessage = "Informe a senha.")]
    [StringLength(128, MinimumLength = 8, ErrorMessage = "A senha deve ter pelo menos 8 caracteres.")]
    [DataType(DataType.Password)]
    [Display(Name = "Senha")]
    public string Password { get; set; } = string.Empty;

    [Required(ErrorMessage = "Confirme a senha.")]
    [Compare(nameof(Password), ErrorMessage = "As senhas não conferem.")]
    [DataType(DataType.Password)]
    [Display(Name = "Confirmar senha")]
    public string ConfirmPassword { get; set; } = string.Empty;
}

public sealed record AuthResponse(string Message, UserDto User);
