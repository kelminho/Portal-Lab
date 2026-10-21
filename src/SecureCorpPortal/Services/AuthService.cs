using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using SecureCorpPortal.Configuration;
using SecureCorpPortal.DTOs;
using SecureCorpPortal.Extensions;
using SecureCorpPortal.Logging;
using SecureCorpPortal.Models;

namespace SecureCorpPortal.Services;

public enum LoginOutcome
{
    Success,
    InvalidCredentials,
    LockedOut,
    Inactive
}

public sealed record LoginResult(LoginOutcome Outcome, UserDto? User = null)
{
    public bool Succeeded => Outcome == LoginOutcome.Success;
}

public static class AuthMessages
{
    /// <summary>
    /// Mensagem única para qualquer falha de login. O motivo real (usuário inexistente,
    /// senha errada, conta bloqueada/inativa) fica apenas na auditoria, evitando
    /// que um visitante descubra quais usuários existem.
    /// </summary>
    public const string InvalidLogin = "Usuário ou senha inválidos, ou conta temporariamente bloqueada.";
}

public interface IAuthService
{
    Task<LoginResult> LoginAsync(string userName, string password, CancellationToken cancellationToken = default);

    Task<ServiceResult<UserDto>> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default);

    Task LogoutAsync(ClaimsPrincipal principal, CancellationToken cancellationToken = default);

    Task<ServiceResult> ChangePasswordAsync(
        CurrentUser user, string currentPassword, string newPassword, CancellationToken cancellationToken = default);
}

/// <summary>
/// Autenticação: login, cadastro, logout e troca de senha.
/// Hash de senha, lockout e emissão do cookie ficam a cargo do ASP.NET Core Identity.
///
/// LAB-EXTENSION-POINT (authentication / session): ver docs/security/extension-points.md.
/// </summary>
public sealed class AuthService : IAuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IAuditService _audit;

    public AuthService(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IAuditService audit)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _audit = audit;
    }

    public async Task<LoginResult> LoginAsync(string userName, string password, CancellationToken cancellationToken = default)
    {
        var attemptedName = LogSanitizer.Clean(userName, 64) ?? string.Empty;
        var user = attemptedName.Length == 0 ? null : await _userManager.FindByNameAsync(attemptedName);

        if (user is null)
        {
            await _audit.RecordAsync(new AuditEntry(AuditEventType.UserLoginFailed, "auth.login", Success: false)
            {
                Username = attemptedName,
                Details = "Usuário inexistente."
            }, cancellationToken);
            return new LoginResult(LoginOutcome.InvalidCredentials);
        }

        if (!user.IsActive)
        {
            await _audit.RecordAsync(new AuditEntry(AuditEventType.UserLoginFailed, "auth.login", Success: false)
            {
                UserId = user.Id,
                Username = user.UserName,
                Details = "Conta desativada."
            }, cancellationToken);
            return new LoginResult(LoginOutcome.Inactive);
        }

        var result = await _signInManager.PasswordSignInAsync(user, password, isPersistent: false, lockoutOnFailure: true);

        if (result.Succeeded)
        {
            user.LastLoginAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            await _audit.RecordAsync(new AuditEntry(AuditEventType.UserLogin, "auth.login")
            {
                UserId = user.Id,
                Username = user.UserName
            }, cancellationToken);

            var role = AppRoles.Highest(await _userManager.GetRolesAsync(user));
            return new LoginResult(LoginOutcome.Success, DtoMapper.ToDto(user, role));
        }

        if (result.IsLockedOut)
        {
            await _audit.RecordAsync(new AuditEntry(AuditEventType.UserLockedOut, "auth.lockout", Success: false)
            {
                UserId = user.Id,
                Username = user.UserName,
                Details = "Conta bloqueada temporariamente por excesso de tentativas inválidas."
            }, cancellationToken);
            return new LoginResult(LoginOutcome.LockedOut);
        }

        await _audit.RecordAsync(new AuditEntry(AuditEventType.UserLoginFailed, "auth.login", Success: false)
        {
            UserId = user.Id,
            Username = user.UserName,
            Details = result.IsNotAllowed ? "Login não permitido para esta conta." : "Senha inválida."
        }, cancellationToken);

        return new LoginResult(LoginOutcome.InvalidCredentials);
    }

    public async Task<ServiceResult<UserDto>> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default)
    {
        var user = new ApplicationUser
        {
            UserName = request.UserName.Trim(),
            Email = request.Email.Trim(),
            FullName = request.FullName.Trim(),
            Department = string.IsNullOrWhiteSpace(request.Department) ? null : request.Department.Trim(),
            IsActive = true,
            CreatedAt = DateTime.UtcNow
        };

        var result = await _userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
        {
            await _audit.RecordAsync(new AuditEntry(AuditEventType.UserCreated, "user.self_registered", Success: false)
            {
                Username = LogSanitizer.Clean(request.UserName, 64),
                Details = "Cadastro rejeitado: " + string.Join(", ", result.Errors.Select(e => e.Code))
            }, cancellationToken);

            return ServiceResult<UserDto>.Fail(ServiceStatus.Invalid, result.Errors.Select(e => e.Description).ToArray());
        }

        // Todo cadastro público recebe o menor privilégio. Promoções são feitas por um ADMIN.
        await _userManager.AddToRoleAsync(user, AppRoles.Guest);

        await _audit.RecordAsync(new AuditEntry(AuditEventType.UserCreated, "user.self_registered")
        {
            UserId = user.Id,
            Username = user.UserName,
            Resource = $"user:{user.Id}",
            Details = $"Conta criada via cadastro público com papel {AppRoles.Guest}."
        }, cancellationToken);

        return ServiceResult<UserDto>.Ok(DtoMapper.ToDto(user, AppRoles.Guest));
    }

    public async Task LogoutAsync(ClaimsPrincipal principal, CancellationToken cancellationToken = default)
    {
        var userId = principal.GetUserId();
        var userName = principal.Identity?.Name;

        await _signInManager.SignOutAsync();

        if (userId is not null)
        {
            await _audit.RecordAsync(new AuditEntry(AuditEventType.UserLogout, "auth.logout")
            {
                UserId = userId,
                Username = userName
            }, cancellationToken);
        }
    }

    public async Task<ServiceResult> ChangePasswordAsync(
        CurrentUser currentUser, string currentPassword, string newPassword, CancellationToken cancellationToken = default)
    {
        var user = await _userManager.FindByIdAsync(currentUser.Id.ToString());
        if (user is null)
        {
            return ServiceResult.Fail(ServiceStatus.NotFound, "Usuário não encontrado.");
        }

        var result = await _userManager.ChangePasswordAsync(user, currentPassword, newPassword);
        if (!result.Succeeded)
        {
            await _audit.RecordAsync(new AuditEntry(AuditEventType.PasswordChanged, "password.change", Success: false)
            {
                Resource = $"user:{user.Id}",
                Details = "Troca de senha rejeitada: " + string.Join(", ", result.Errors.Select(e => e.Code))
            }, cancellationToken);

            return ServiceResult.Fail(ServiceStatus.Invalid, result.Errors.Select(e => e.Description).ToArray());
        }

        // A troca de senha altera o security stamp; renova o cookie da sessão atual.
        await _signInManager.RefreshSignInAsync(user);

        await _audit.RecordAsync(new AuditEntry(AuditEventType.PasswordChanged, "password.change")
        {
            Resource = $"user:{user.Id}"
        }, cancellationToken);

        return ServiceResult.Ok();
    }
}
