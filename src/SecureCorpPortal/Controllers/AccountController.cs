using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureCorpPortal.DTOs;
using SecureCorpPortal.Models;
using SecureCorpPortal.Models.ViewModels;
using SecureCorpPortal.Services;

namespace SecureCorpPortal.Controllers;

/// <summary>Páginas de login, cadastro, logout e acesso negado.</summary>
public class AccountController : PortalControllerBase
{
    private readonly IAuthService _auth;
    private readonly IAuditService _audit;

    public AccountController(IAuthService auth, IAuditService audit)
    {
        _auth = auth;
        _audit = audit;
    }

    [AllowAnonymous]
    [HttpGet("/login")]
    public IActionResult Login(string? returnUrl = null)
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            return RedirectToAction("Index", "Dashboard");
        }

        return View(new LoginViewModel { ReturnUrl = returnUrl });
    }

    [AllowAnonymous]
    [HttpPost("/login")]
    public async Task<IActionResult> Login(LoginViewModel model, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var result = await _auth.LoginAsync(model.UserName, model.Password, cancellationToken);
        if (result.Succeeded)
        {
            // Evita "open redirect": só aceita URLs locais.
            if (!string.IsNullOrEmpty(model.ReturnUrl))
            {
                if (Url.IsLocalUrl(model.ReturnUrl))
                {
                    return LocalRedirect(model.ReturnUrl);
                }

                // O usuário ainda não está autenticado nesta requisição (o cookie vai na resposta),
                // por isso o ator é informado explicitamente.
                await _audit.RecordAsync(new AuditEntry(AuditEventType.AccessDenied, "login.external_return_url_blocked", Success: false)
                {
                    UserId = result.User!.Id,
                    Username = result.User.UserName,
                    Resource = model.ReturnUrl,
                    Details = "returnUrl externo ignorado após o login; redirecionado ao dashboard."
                }, cancellationToken);
            }

            return RedirectToAction("Index", "Dashboard");
        }

        ModelState.AddModelError(string.Empty, AuthMessages.InvalidLogin);
        return View(model);
    }

    [AllowAnonymous]
    [HttpGet("/register")]
    public IActionResult Register()
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            return RedirectToAction("Index", "Dashboard");
        }

        return View(new RegisterRequest());
    }

    [AllowAnonymous]
    [HttpPost("/register")]
    public async Task<IActionResult> Register(RegisterRequest model, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var result = await _auth.RegisterAsync(model, cancellationToken);
        if (result.Succeeded)
        {
            FlashSuccess("Conta criada com sucesso. Seu acesso inicial é de convidado (GUEST). Faça login para continuar.");
            return RedirectToAction(nameof(Login));
        }

        AddErrors(result);
        return View(model);
    }

    [Authorize]
    [HttpPost("/logout")]
    public async Task<IActionResult> Logout(CancellationToken cancellationToken)
    {
        await _auth.LogoutAsync(User, cancellationToken);
        FlashSuccess("Sessão encerrada.");
        return RedirectToAction(nameof(Login));
    }

    [AllowAnonymous]
    [HttpGet("/access-denied")]
    public IActionResult AccessDenied()
    {
        Response.StatusCode = StatusCodes.Status403Forbidden;
        return View();
    }
}
