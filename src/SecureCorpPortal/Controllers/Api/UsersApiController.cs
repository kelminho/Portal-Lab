using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureCorpPortal.Configuration;
using SecureCorpPortal.DTOs;
using SecureCorpPortal.Services;

namespace SecureCorpPortal.Controllers.Api;

/// <summary>
/// GET    /api/users        lista (ADMIN, ANALYST)
/// GET    /api/users/{id}   próprio usuário, ou qualquer um para ADMIN/ANALYST
/// PUT    /api/users/{id}   próprio perfil, ou qualquer um para ADMIN (papel/status só ADMIN)
/// DELETE /api/users/{id}   ADMIN
///
/// LAB-EXTENSION-POINT (API security / IDOR): ver docs/security/extension-points.md.
/// </summary>
[Authorize]
[Route("api/users")]
public class UsersApiController : ApiControllerBase
{
    private readonly IUserService _users;

    public UsersApiController(IUserService users)
    {
        _users = users;
    }

    [HttpGet("")]
    [Authorize(Policy = Policies.CanViewUserDirectory)]
    [ProducesResponseType(typeof(IReadOnlyList<UserDto>), StatusCodes.Status200OK)]
    public async Task<ActionResult<IReadOnlyList<UserDto>>> GetAll(CancellationToken cancellationToken) =>
        Ok(await _users.GetAllAsync(cancellationToken));

    [HttpGet("{id:int}")]
    [ProducesResponseType(typeof(UserDto), StatusCodes.Status200OK)]
    public async Task<ActionResult<UserDto>> GetById(int id, CancellationToken cancellationToken)
    {
        var result = await _users.GetByIdAsync(id, CurrentUser, cancellationToken);
        return result.Succeeded ? Ok(result.Value) : Failure(result);
    }

    [HttpPut("{id:int}")]
    [ProducesResponseType(typeof(UserDto), StatusCodes.Status200OK)]
    public async Task<ActionResult<UserDto>> Update(int id, UpdateUserRequest request, CancellationToken cancellationToken)
    {
        var result = await _users.UpdateAsync(id, request, CurrentUser, cancellationToken);
        return result.Succeeded ? Ok(result.Value) : Failure(result);
    }

    [HttpDelete("{id:int}")]
    [Authorize(Policy = Policies.AdminOnly)]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Delete(int id, CancellationToken cancellationToken)
    {
        var result = await _users.DeleteAsync(id, CurrentUser, cancellationToken);
        return result.Succeeded ? NoContent() : Failure(result);
    }
}
