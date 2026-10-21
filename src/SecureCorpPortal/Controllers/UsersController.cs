using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureCorpPortal.Configuration;
using SecureCorpPortal.Models.ViewModels;
using SecureCorpPortal.Services;

namespace SecureCorpPortal.Controllers;

/// <summary>Diretório de usuários (somente leitura) para ADMIN e ANALYST.</summary>
[Authorize(Policy = Policies.CanViewUserDirectory)]
public class UsersController : PortalControllerBase
{
    private readonly IUserService _users;

    public UsersController(IUserService users)
    {
        _users = users;
    }

    [HttpGet("/users")]
    public async Task<IActionResult> Index(string? q, CancellationToken cancellationToken)
    {
        var query = q?.Trim();
        var users = string.IsNullOrEmpty(query)
            ? await _users.GetAllAsync(cancellationToken)
            : await _users.SearchAsync(query[..Math.Min(query.Length, 100)], 100, cancellationToken);

        return View(new UserDirectoryViewModel { Query = query, Users = users });
    }

    [HttpGet("/users/{id:int}")]
    public async Task<IActionResult> Details(int id, CancellationToken cancellationToken)
    {
        var result = await _users.GetByIdAsync(id, CurrentUser, cancellationToken);
        return result.Succeeded ? View(result.Value) : FromFailure(result);
    }
}
