using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Mvc;
using WebSegura.Models;
using WebSegura.Services;

namespace WebSegura.Controllers;

public class AccountController : Controller
{
    private readonly SecurityService _security;
    private readonly ILogger<AccountController> _logger;

    public AccountController(SecurityService security, ILogger<AccountController> logger)
    {
        _security = security;
        _logger   = logger;
    }

    // GET /login
    [HttpGet("/login")]
    public IActionResult Login(string? denied)
    {
        // Se já autenticado, redireciona para página correta
        var role = HttpContext.Session.GetString("UserRole");
        if (!string.IsNullOrEmpty(role))
            return RedirectByRole(role);

        var vm = new LoginViewModel();
        if (denied == "1")
            vm.ErrorMessage = "Acesso negado. Faça login para continuar.";
        return View(vm);
    }

    // POST /login  — token CSRF validado automaticamente pelo [ValidateAntiForgeryToken]
    [HttpPost("/login")]
    [ValidateAntiForgeryToken]  // PROTEÇÃO CSRF: rejeita requests sem token válido
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        try
        {
            // Validação básica de entrada (sanitização)
            if (string.IsNullOrWhiteSpace(model.Username) ||
                string.IsNullOrWhiteSpace(model.Password))
            {
                model.ErrorMessage = "Usuário e senha são obrigatórios.";
                return View(model);
            }

            // Limita tamanho para prevenir ataques de DoS
            if (model.Username.Length > 100 || model.Password.Length > 200)
            {
                model.ErrorMessage = "Dados inválidos.";
                return View(model);
            }

            // Busca usuário via consulta parametrizada (sem SQL injection)
            var user = await _security.GetUserByUsernameAsync(model.Username.Trim());

            // Verifica hash da senha com Argon2id
            if (user == null || !_security.VerifyPassword(model.Password, user.PasswordHash))
            {
                // Mensagem genérica — não revela se usuário existe ou não
                model.ErrorMessage = "Usuário ou senha inválidos.";
                _logger.LogWarning("Tentativa de login falhou: usuário={User}", model.Username);
                return View(model);
            }

            // ── SEGURANÇA DE SESSÃO ──────────────────────────────
            // Regenera o ID de sessão após login bem-sucedido
            // para prevenir ataques de Session Fixation
            HttpContext.Session.Clear();

            // Armazena dados mínimos necessários na sessão
            HttpContext.Session.SetInt32("UserId",   user.Id);
            HttpContext.Session.SetString("Username", user.Username);
            HttpContext.Session.SetString("UserRole", user.Role);

            _logger.LogInformation("Login bem-sucedido: usuário={User}, role={Role}",
                user.Username, user.Role);

            return RedirectByRole(user.Role);
        }
        catch (Exception ex)
        {
            // Trata erro sem expor detalhes ao usuário
            _logger.LogError(ex, "Erro interno no login");
            model.ErrorMessage = "Ocorreu um erro. Tente novamente.";
            return View(model);
        }
    }

    // POST /logout — protegido contra CSRF
    [HttpPost("/logout")]
    [ValidateAntiForgeryToken]
    public IActionResult Logout()
    {
        try
        {
            var username = HttpContext.Session.GetString("Username");
            _logger.LogInformation("Logout: usuário={User}", username);

            // Invalida sessão completamente
            HttpContext.Session.Clear();
            return Redirect("/login");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro no logout");
            return Redirect("/login");
        }
    }

    private IActionResult RedirectByRole(string role) =>
        role == Roles.Admin
            ? Redirect("/administradores")
            : Redirect("/usuarios");
}
