using System.ComponentModel.DataAnnotations;
using SecureCorpPortal.DTOs;

namespace SecureCorpPortal.Models.ViewModels;

public sealed class LoginViewModel
{
    [Required(ErrorMessage = "Informe o usuário.")]
    [StringLength(64)]
    [Display(Name = "Usuário")]
    public string UserName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Informe a senha.")]
    [StringLength(128)]
    [DataType(DataType.Password)]
    [Display(Name = "Senha")]
    public string Password { get; set; } = string.Empty;

    /// <summary>Página para onde voltar após o login (validada com Url.IsLocalUrl).</summary>
    public string? ReturnUrl { get; set; }
}

public sealed class ProfileFormModel
{
    [Required(ErrorMessage = "Informe o nome completo.")]
    [StringLength(100)]
    [Display(Name = "Nome completo")]
    public string FullName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Informe o e-mail.")]
    [EmailAddress(ErrorMessage = "E-mail inválido.")]
    [StringLength(256)]
    [Display(Name = "E-mail")]
    public string Email { get; set; } = string.Empty;

    [StringLength(100)]
    [Display(Name = "Departamento")]
    public string? Department { get; set; }

    [StringLength(100)]
    [Display(Name = "Cargo")]
    public string? JobTitle { get; set; }

    public static ProfileFormModel From(UserDto user) => new()
    {
        FullName = user.FullName,
        Email = user.Email,
        Department = user.Department,
        JobTitle = user.JobTitle
    };
}

public sealed class ChangePasswordModel
{
    [Required(ErrorMessage = "Informe a senha atual.")]
    [DataType(DataType.Password)]
    [Display(Name = "Senha atual")]
    public string CurrentPassword { get; set; } = string.Empty;

    [Required(ErrorMessage = "Informe a nova senha.")]
    [StringLength(128, MinimumLength = 8, ErrorMessage = "A senha deve ter pelo menos 8 caracteres.")]
    [DataType(DataType.Password)]
    [Display(Name = "Nova senha")]
    public string NewPassword { get; set; } = string.Empty;

    [Required(ErrorMessage = "Confirme a nova senha.")]
    [Compare(nameof(NewPassword), ErrorMessage = "As senhas não conferem.")]
    [DataType(DataType.Password)]
    [Display(Name = "Confirmar nova senha")]
    public string ConfirmNewPassword { get; set; } = string.Empty;
}

public sealed class ProfilePageViewModel
{
    public required UserDto User { get; init; }

    public ProfileFormModel Profile { get; init; } = new();

    public ChangePasswordModel Password { get; init; } = new();
}
