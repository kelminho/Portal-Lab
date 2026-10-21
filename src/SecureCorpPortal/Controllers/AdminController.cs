using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using SecureCorpPortal.Configuration;
using SecureCorpPortal.DTOs;
using SecureCorpPortal.Lab;
using SecureCorpPortal.Models;
using SecureCorpPortal.Models.ViewModels;
using SecureCorpPortal.Services;

namespace SecureCorpPortal.Controllers;

/// <summary>Área administrativa (somente ADMIN): visão geral, usuários e auditoria.</summary>
[Authorize(Policy = Policies.AdminOnly)]
[Route("admin")]
public class AdminController : PortalControllerBase
{
    private readonly IUserService _users;
    private readonly IAuditService _audit;
    private readonly IDashboardService _dashboard;
    private readonly LabModuleCatalog _labCatalog;

    public AdminController(IUserService users, IAuditService audit, IDashboardService dashboard, LabModuleCatalog labCatalog)
    {
        _users = users;
        _audit = audit;
        _dashboard = dashboard;
        _labCatalog = labCatalog;
    }

    [HttpGet("")]
    public async Task<IActionResult> Index(CancellationToken cancellationToken) =>
        View(new AdminIndexViewModel
        {
            Dashboard = await _dashboard.GetAsync(CurrentUser, cancellationToken),
            Lab = _labCatalog
        });

    [HttpGet("users")]
    public async Task<IActionResult> Users(CancellationToken cancellationToken) =>
        View(await _users.GetAllForAdminAsync(cancellationToken));

    [HttpGet("users/{id:int}/edit")]
    public async Task<IActionResult> EditUser(int id, CancellationToken cancellationToken)
    {
        var result = await _users.GetByIdAsync(id, CurrentUser, cancellationToken);
        if (!result.Succeeded)
        {
            return FromFailure(result);
        }

        var user = result.Value!;
        return View(PopulateEditModel(new AdminEditUserViewModel
        {
            Id = user.Id,
            UserName = user.UserName,
            FullName = user.FullName,
            Email = user.Email,
            Department = user.Department,
            JobTitle = user.JobTitle,
            Role = user.Role,
            IsActive = user.IsActive
        }));
    }

    [HttpPost("users/{id:int}/edit")]
    public async Task<IActionResult> EditUser(int id, AdminEditUserViewModel model, CancellationToken cancellationToken)
    {
        model.Id = id;
        if (!ModelState.IsValid)
        {
            return View(PopulateEditModel(model));
        }

        // O próprio admin não altera seu papel/status por esta tela (campos desabilitados na view).
        var isSelf = id == CurrentUser.Id;
        var request = new UpdateUserRequest
        {
            FullName = model.FullName,
            Email = model.Email,
            Department = model.Department ?? string.Empty,
            JobTitle = model.JobTitle ?? string.Empty,
            Role = isSelf ? null : model.Role,
            IsActive = isSelf ? null : model.IsActive
        };

        var result = await _users.UpdateAsync(id, request, CurrentUser, cancellationToken);
        if (result.Succeeded)
        {
            FlashSuccess($"Usuário '{result.Value!.UserName}' atualizado.");
            return RedirectToAction(nameof(Users));
        }

        if (result.Status != ServiceStatus.Invalid)
        {
            return FromFailure(result);
        }

        AddErrors(result);
        return View(PopulateEditModel(model));
    }

    [HttpPost("users/{id:int}/delete")]
    public async Task<IActionResult> DeleteUser(int id, CancellationToken cancellationToken)
    {
        var result = await _users.DeleteAsync(id, CurrentUser, cancellationToken);
        if (result.Succeeded)
        {
            FlashSuccess("Usuário excluído.");
        }
        else
        {
            FlashError(string.Join(" ", result.Errors));
        }

        return RedirectToAction(nameof(Users));
    }

    [HttpPost("users/{id:int}/unlock")]
    public async Task<IActionResult> UnlockUser(int id, CancellationToken cancellationToken)
    {
        var result = await _users.UnlockAsync(id, CurrentUser, cancellationToken);
        if (result.Succeeded)
        {
            FlashSuccess("Bloqueio removido.");
        }
        else
        {
            FlashError(string.Join(" ", result.Errors));
        }

        return RedirectToAction(nameof(Users));
    }

    [HttpGet("logs")]
    public async Task<IActionResult> Logs([FromQuery] AuditQuery query, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            query = new AuditQuery();
        }

        // Quem consulta a auditoria também é auditado.
        await _audit.RecordAsync(new AuditEntry(AuditEventType.AdminAction, "audit_log.viewed")
        {
            Severity = AuditSeverity.Low
        }, cancellationToken);

        var result = await _audit.QueryAsync(query, cancellationToken);
        return View(new AuditLogViewModel { Query = query, Result = result });
    }

    private AdminEditUserViewModel PopulateEditModel(AdminEditUserViewModel model)
    {
        model.IsSelf = model.Id == CurrentUser.Id;
        model.RoleOptions = AppRoles.All
            .Select(r => new SelectListItem(r, r, r == model.Role))
            .ToList();
        return model;
    }
}
