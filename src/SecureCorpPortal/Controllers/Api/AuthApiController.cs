using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureCorpPortal.DTOs;
using SecureCorpPortal.Services;

namespace SecureCorpPortal.Controllers.Api;

/// <summary>
/// POST /api/auth/login     autentica e emite o cookie de sessão
/// POST /api/auth/register  cria conta com papel GUEST
/// POST /api/auth/logout    encerra a sessão
/// GET  /api/auth/me        dados do usuário autenticado
/// </summary>
[Route("api/auth")]
public class AuthApiController : ApiControllerBase
{
    private readonly IAuthService _auth;
    private readonly IUserService _users;

    public AuthApiController(IAuthService auth, IUserService users)
    {
        _auth = auth;
        _users = users;
    }

    [AllowAnonymous]
    [HttpPost("login")]
    [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<AuthResponse>> Login(LoginRequest request, CancellationToken cancellationToken)
    {
        var result = await _auth.LoginAsync(request.UserName, request.Password, cancellationToken);
        if (!result.Succeeded)
        {
            return Problem(statusCode: StatusCodes.Status401Unauthorized, title: AuthMessages.InvalidLogin);
        }

        return Ok(new AuthResponse("Login realizado com sucesso.", result.User!));
    }

    [AllowAnonymous]
    [HttpPost("register")]
    [ProducesResponseType(typeof(UserDto), StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<UserDto>> Register(RegisterRequest request, CancellationToken cancellationToken)
    {
        var result = await _auth.RegisterAsync(request, cancellationToken);
        if (!result.Succeeded)
        {
            return Failure(result);
        }

        return Created($"/api/users/{result.Value!.Id}", result.Value);
    }

    [Authorize]
    [HttpPost("logout")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Logout(CancellationToken cancellationToken)
    {
        await _auth.LogoutAsync(User, cancellationToken);
        return NoContent();
    }

    [Authorize]
    [HttpGet("me")]
    [ProducesResponseType(typeof(UserDto), StatusCodes.Status200OK)]
    public async Task<ActionResult<UserDto>> Me(CancellationToken cancellationToken)
    {
        var result = await _users.GetByIdAsync(CurrentUser.Id, CurrentUser, cancellationToken);
        return result.Succeeded ? Ok(result.Value) : Failure(result);
    }
}
