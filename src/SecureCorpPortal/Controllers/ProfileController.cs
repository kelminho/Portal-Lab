using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureCorpPortal.DTOs;
using SecureCorpPortal.Models.ViewModels;
using SecureCorpPortal.Services;

namespace SecureCorpPortal.Controllers;

/// <summary>Perfil do usuário logado: dados pessoais e troca de senha.</summary>
[Authorize]
public class ProfileController : PortalControllerBase
{
    private readonly IUserService _users;
    private readonly IAuthService _auth;

    public ProfileController(IUserService users, IAuthService auth)
    {
        _users = users;
        _auth = auth;
    }

    [HttpGet("/profile")]
    public async Task<IActionResult> Index(CancellationToken cancellationToken)
    {
        var page = await BuildPageAsync(null, null, cancellationToken);
        return page is null ? NotFound() : View(page);
    }

    [HttpPost("/profile")]
    public async Task<IActionResult> Update([Bind(Prefix = "Profile")] ProfileFormModel model, CancellationToken cancellationToken)
    {
        if (ModelState.IsValid)
        {
            // Role e IsActive NÃO são enviados: o perfil só altera dados pessoais.
            var request = new UpdateUserRequest
            {
                FullName = model.FullName,
                Email = model.Email,
                Department = model.Department ?? string.Empty,
                JobTitle = model.JobTitle ?? string.Empty
            };

            var result = await _users.UpdateAsync(CurrentUser.Id, request, CurrentUser, cancellationToken);
            if (result.Succeeded)
            {
                FlashSuccess("Perfil atualizado.");
                return RedirectToAction(nameof(Index));
            }

            if (result.Status != ServiceStatus.Invalid)
            {
                return FromFailure(result);
            }

            AddErrors(result);
        }

        var page = await BuildPageAsync(model, null, cancellationToken);
        return page is null ? NotFound() : View("Index", page);
    }

    [HttpPost("/profile/password")]
    public async Task<IActionResult> ChangePassword([Bind(Prefix = "Password")] ChangePasswordModel model,
        CancellationToken cancellationToken)
    {
        if (ModelState.IsValid)
        {
            var result = await _auth.ChangePasswordAsync(CurrentUser, model.CurrentPassword, model.NewPassword, cancellationToken);
            if (result.Succeeded)
            {
                FlashSuccess("Senha alterada com sucesso.");
                return RedirectToAction(nameof(Index));
            }

            AddErrors(result);
        }

        var page = await BuildPageAsync(null, new ChangePasswordModel(), cancellationToken);
        return page is null ? NotFound() : View("Index", page);
    }

    private async Task<ProfilePageViewModel?> BuildPageAsync(
        ProfileFormModel? profile, ChangePasswordModel? password, CancellationToken cancellationToken)
    {
        var result = await _users.GetByIdAsync(CurrentUser.Id, CurrentUser, cancellationToken);
        if (!result.Succeeded)
        {
            return null;
        }

        var user = result.Value!;
        return new ProfilePageViewModel
        {
            User = user,
            Profile = profile ?? ProfileFormModel.From(user),
            Password = password ?? new ChangePasswordModel()
        };
    }
}
