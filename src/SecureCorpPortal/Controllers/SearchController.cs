using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureCorpPortal.Configuration;
using SecureCorpPortal.Models.ViewModels;
using SecureCorpPortal.Services;

namespace SecureCorpPortal.Controllers;

/// <summary>
/// Busca global. Documentos são sempre filtrados pelas permissões do usuário;
/// usuários só aparecem para quem pode ver o diretório (ADMIN/ANALYST).
///
/// LAB-EXTENSION-POINT (input validation): ver docs/security/extension-points.md.
/// </summary>
[Authorize]
public class SearchController : PortalControllerBase
{
    private const int MaxQueryLength = 100;

    private readonly IDocumentService _documents;
    private readonly IUserService _users;
    private readonly IAuthorizationService _authorization;

    public SearchController(IDocumentService documents, IUserService users, IAuthorizationService authorization)
    {
        _documents = documents;
        _users = users;
        _authorization = authorization;
    }

    [HttpGet("/search")]
    public async Task<IActionResult> Index(string? q, CancellationToken cancellationToken)
    {
        var query = q?.Trim();
        if (query?.Length > MaxQueryLength)
        {
            query = query[..MaxQueryLength];
        }

        var canSearchUsers = (await _authorization.AuthorizeAsync(User, Policies.CanViewUserDirectory)).Succeeded;

        if (string.IsNullOrEmpty(query))
        {
            return View(new SearchViewModel { CanSearchUsers = canSearchUsers });
        }

        var documents = await _documents.SearchAsync(CurrentUser, query, cancellationToken);
        var users = canSearchUsers ? await _users.SearchAsync(query, 25, cancellationToken) : [];

        return View(new SearchViewModel
        {
            Query = query,
            CanSearchUsers = canSearchUsers,
            Documents = documents,
            Users = users
        });
    }
}
