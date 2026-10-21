using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SecureCorpPortal.Configuration;
using SecureCorpPortal.Data;
using SecureCorpPortal.DTOs;
using SecureCorpPortal.Models;

namespace SecureCorpPortal.Services;

public interface IUserService
{
    Task<IReadOnlyList<UserDto>> GetAllAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<AdminUserDto>> GetAllForAdminAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<UserDto>> SearchAsync(string term, int take, CancellationToken cancellationToken = default);

    Task<ServiceResult<UserDto>> GetByIdAsync(int id, CurrentUser actor, CancellationToken cancellationToken = default);

    Task<ServiceResult<UserDto>> UpdateAsync(int id, UpdateUserRequest request, CurrentUser actor,
        CancellationToken cancellationToken = default);

    Task<ServiceResult> DeleteAsync(int id, CurrentUser actor, CancellationToken cancellationToken = default);

    Task<ServiceResult> UnlockAsync(int id, CurrentUser actor, CancellationToken cancellationToken = default);
}

/// <summary>
/// Gerenciamento de usuários. O UserManager do Identity já funciona como
/// "repositório" de usuários (valida, normaliza e persiste), por isso não há um
/// UserRepository separado. Consultas de listagem usam o DbContext diretamente.
///
/// Regras:
/// - ler outro usuário: ADMIN ou ANALYST (ou o próprio usuário);
/// - alterar perfil: o próprio usuário ou ADMIN;
/// - alterar papel/status, excluir, desbloquear: somente ADMIN;
/// - um ADMIN não pode rebaixar, desativar ou excluir a si mesmo.
///
/// LAB-EXTENSION-POINT (access control / privilege management): ver docs/security/extension-points.md.
/// </summary>
public sealed class UserService : IUserService
{
    private readonly AppDbContext _db;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IAuditService _audit;

    public UserService(AppDbContext db, UserManager<ApplicationUser> userManager, IAuditService audit)
    {
        _db = db;
        _userManager = userManager;
        _audit = audit;
    }

    public async Task<IReadOnlyList<UserDto>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        var users = await _db.Users.AsNoTracking().OrderBy(u => u.UserName).ToListAsync(cancellationToken);
        var roles = await GetRoleMapAsync(cancellationToken);
        return users.Select(u => DtoMapper.ToDto(u, RoleOf(roles, u.Id))).ToList();
    }

    public async Task<IReadOnlyList<AdminUserDto>> GetAllForAdminAsync(CancellationToken cancellationToken = default)
    {
        var users = await _db.Users.AsNoTracking().OrderBy(u => u.UserName).ToListAsync(cancellationToken);
        var roles = await GetRoleMapAsync(cancellationToken);
        return users.Select(u => DtoMapper.ToAdminDto(u, RoleOf(roles, u.Id))).ToList();
    }

    public async Task<IReadOnlyList<UserDto>> SearchAsync(string term, int take, CancellationToken cancellationToken = default)
    {
        var normalized = term.Trim().ToLower();
        var users = await _db.Users.AsNoTracking()
            .Where(u =>
                (u.UserName != null && u.UserName.ToLower().Contains(normalized)) ||
                u.FullName.ToLower().Contains(normalized) ||
                (u.Email != null && u.Email.ToLower().Contains(normalized)) ||
                (u.Department != null && u.Department.ToLower().Contains(normalized)))
            .OrderBy(u => u.UserName)
            .Take(take)
            .ToListAsync(cancellationToken);

        var roles = await GetRoleMapAsync(cancellationToken);
        return users.Select(u => DtoMapper.ToDto(u, RoleOf(roles, u.Id))).ToList();
    }

    public async Task<ServiceResult<UserDto>> GetByIdAsync(int id, CurrentUser actor, CancellationToken cancellationToken = default)
    {
        var canReadOthers = actor.IsAdmin || actor.IsAnalyst;
        if (actor.Id != id && !canReadOthers)
        {
            await DenyAsync("user.read_denied", id, "Tentativa de consultar dados de outro usuário.", cancellationToken);
            return ServiceResult<UserDto>.Fail(ServiceStatus.Forbidden, "Você só pode consultar o próprio perfil.");
        }

        var user = await _userManager.FindByIdAsync(id.ToString());
        if (user is null)
        {
            return ServiceResult<UserDto>.Fail(ServiceStatus.NotFound, "Usuário não encontrado.");
        }

        return ServiceResult<UserDto>.Ok(DtoMapper.ToDto(user, await GetRoleAsync(user)));
    }

    public async Task<ServiceResult<UserDto>> UpdateAsync(
        int id, UpdateUserRequest request, CurrentUser actor, CancellationToken cancellationToken = default)
    {
        var isSelf = actor.Id == id;

        if (!isSelf && !actor.IsAdmin)
        {
            await DenyAsync("user.update_denied", id, "Tentativa de alterar o perfil de outro usuário.", cancellationToken);
            return ServiceResult<UserDto>.Fail(ServiceStatus.Forbidden, "Você só pode alterar o próprio perfil.");
        }

        // Proteção contra escalonamento de privilégio: só ADMIN altera papel ou status.
        if ((request.Role is not null || request.IsActive is not null) && !actor.IsAdmin)
        {
            await DenyAsync("user.privilege_change_denied", id,
                "Tentativa de alterar papel ou status sem privilégio administrativo.", cancellationToken,
                AuditSeverity.High);
            return ServiceResult<UserDto>.Fail(ServiceStatus.Forbidden, "Somente administradores podem alterar papel ou status.");
        }

        var user = await _userManager.FindByIdAsync(id.ToString());
        if (user is null)
        {
            return ServiceResult<UserDto>.Fail(ServiceStatus.NotFound, "Usuário não encontrado.");
        }

        var currentRole = await GetRoleAsync(user);

        string? newRole = null;
        if (request.Role is not null)
        {
            newRole = AppRoles.Normalize(request.Role);
            if (newRole is null)
            {
                return ServiceResult<UserDto>.Fail(ServiceStatus.Invalid,
                    $"Papel inválido. Valores aceitos: {string.Join(", ", AppRoles.All)}.");
            }

            if (isSelf && newRole != currentRole)
            {
                return ServiceResult<UserDto>.Fail(ServiceStatus.Invalid, "Um administrador não pode alterar o próprio papel.");
            }
        }

        if (isSelf && request.IsActive == false)
        {
            return ServiceResult<UserDto>.Fail(ServiceStatus.Invalid, "Um administrador não pode desativar a própria conta.");
        }

        var changedFields = ApplyProfileChanges(user, request);
        var statusChanged = request.IsActive is { } isActive && isActive != user.IsActive;
        if (statusChanged)
        {
            user.IsActive = request.IsActive!.Value;
            changedFields.Add("is_active");
        }

        if (changedFields.Count > 0)
        {
            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
            {
                return ServiceResult<UserDto>.Fail(ServiceStatus.Invalid,
                    updateResult.Errors.Select(e => e.Description).ToArray());
            }
        }

        var roleChanged = newRole is not null && newRole != currentRole;
        if (roleChanged)
        {
            await _userManager.RemoveFromRolesAsync(user, await _userManager.GetRolesAsync(user));
            await _userManager.AddToRoleAsync(user, newRole!);

            await _audit.RecordAsync(new AuditEntry(AuditEventType.RoleChanged, "user.role_changed")
            {
                Resource = $"user:{user.Id}",
                Details = $"Papel de '{user.UserName}' alterado de {currentRole} para {newRole}."
            }, cancellationToken);

            currentRole = newRole!;
        }

        if (statusChanged)
        {
            await _audit.RecordAsync(new AuditEntry(AuditEventType.AdminAction,
                user.IsActive ? "user.activated" : "user.deactivated")
            {
                Resource = $"user:{user.Id}",
                Details = $"Conta '{user.UserName}' {(user.IsActive ? "ativada" : "desativada")}."
            }, cancellationToken);
        }

        // Invalida sessões existentes do usuário alterado (efetivo no próximo ciclo de validação).
        if (roleChanged || statusChanged)
        {
            await _userManager.UpdateSecurityStampAsync(user);
        }

        if (changedFields.Count > 0)
        {
            await _audit.RecordAsync(new AuditEntry(AuditEventType.UserUpdated, isSelf ? "user.profile_updated" : "user.updated_by_admin")
            {
                Resource = $"user:{user.Id}",
                Details = "Campos alterados: " + string.Join(", ", changedFields)
            }, cancellationToken);
        }

        return ServiceResult<UserDto>.Ok(DtoMapper.ToDto(user, currentRole));
    }

    public async Task<ServiceResult> DeleteAsync(int id, CurrentUser actor, CancellationToken cancellationToken = default)
    {
        if (!actor.IsAdmin)
        {
            await DenyAsync("user.delete_denied", id, "Tentativa de excluir usuário sem privilégio administrativo.",
                cancellationToken, AuditSeverity.High);
            return ServiceResult.Fail(ServiceStatus.Forbidden, "Somente administradores podem excluir usuários.");
        }

        if (actor.Id == id)
        {
            return ServiceResult.Fail(ServiceStatus.Invalid, "Um administrador não pode excluir a própria conta.");
        }

        var user = await _userManager.FindByIdAsync(id.ToString());
        if (user is null)
        {
            return ServiceResult.Fail(ServiceStatus.NotFound, "Usuário não encontrado.");
        }

        var userName = user.UserName;
        var result = await _userManager.DeleteAsync(user);
        if (!result.Succeeded)
        {
            return ServiceResult.Fail(ServiceStatus.Invalid, result.Errors.Select(e => e.Description).ToArray());
        }

        await _audit.RecordAsync(new AuditEntry(AuditEventType.UserDeleted, "user.deleted")
        {
            Resource = $"user:{id}",
            Details = $"Conta '{userName}' excluída."
        }, cancellationToken);

        return ServiceResult.Ok();
    }

    public async Task<ServiceResult> UnlockAsync(int id, CurrentUser actor, CancellationToken cancellationToken = default)
    {
        if (!actor.IsAdmin)
        {
            return ServiceResult.Fail(ServiceStatus.Forbidden, "Somente administradores podem desbloquear contas.");
        }

        var user = await _userManager.FindByIdAsync(id.ToString());
        if (user is null)
        {
            return ServiceResult.Fail(ServiceStatus.NotFound, "Usuário não encontrado.");
        }

        await _userManager.SetLockoutEndDateAsync(user, null);
        await _userManager.ResetAccessFailedCountAsync(user);

        await _audit.RecordAsync(new AuditEntry(AuditEventType.AdminAction, "user.unlocked")
        {
            Resource = $"user:{id}",
            Details = $"Bloqueio da conta '{user.UserName}' removido."
        }, cancellationToken);

        return ServiceResult.Ok();
    }

    private static List<string> ApplyProfileChanges(ApplicationUser user, UpdateUserRequest request)
    {
        var changed = new List<string>();

        if (request.FullName is { } fullName && fullName.Trim() != user.FullName)
        {
            user.FullName = fullName.Trim();
            changed.Add("full_name");
        }

        if (request.Email is { } email && !string.Equals(email.Trim(), user.Email, StringComparison.OrdinalIgnoreCase))
        {
            user.Email = email.Trim();
            changed.Add("email");
        }

        if (request.Department is { } department && NullIfEmpty(department) != user.Department)
        {
            user.Department = NullIfEmpty(department);
            changed.Add("department");
        }

        if (request.JobTitle is { } jobTitle && NullIfEmpty(jobTitle) != user.JobTitle)
        {
            user.JobTitle = NullIfEmpty(jobTitle);
            changed.Add("job_title");
        }

        return changed;
    }

    private static string? NullIfEmpty(string value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private Task DenyAsync(string action, int targetUserId, string details, CancellationToken cancellationToken,
        AuditSeverity? severity = null) =>
        _audit.RecordAsync(new AuditEntry(AuditEventType.AccessDenied, action, Success: false)
        {
            Resource = $"user:{targetUserId}",
            Details = details,
            Severity = severity
        }, cancellationToken);

    private async Task<string> GetRoleAsync(ApplicationUser user) =>
        AppRoles.Highest(await _userManager.GetRolesAsync(user));

    private async Task<Dictionary<int, List<string>>> GetRoleMapAsync(CancellationToken cancellationToken)
    {
        var rows = await (from userRole in _db.UserRoles
                          join role in _db.Roles on userRole.RoleId equals role.Id
                          select new { userRole.UserId, role.Name })
            .ToListAsync(cancellationToken);

        return rows
            .GroupBy(r => r.UserId)
            .ToDictionary(g => g.Key, g => g.Select(r => r.Name ?? AppRoles.Guest).ToList());
    }

    private static string RoleOf(Dictionary<int, List<string>> roles, int userId) =>
        roles.TryGetValue(userId, out var list) ? AppRoles.Highest(list) : AppRoles.Guest;
}
