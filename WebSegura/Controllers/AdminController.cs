using Microsoft.AspNetCore.Mvc;
using WebSegura.Models;
using WebSegura.Services;

namespace WebSegura.Controllers;

public class AdminController : Controller
{
    private readonly SecurityService _security;
    private readonly ILogger<AdminController> _logger;

    public AdminController(SecurityService security, ILogger<AdminController> logger)
    {
        _security = security;
        _logger   = logger;
    }

    // GET /administradores — só admins (verificado pelo middleware)
    [HttpGet("/administradores")]
    public IActionResult Index()
    {
        var username = HttpContext.Session.GetString("Username");
        ViewBag.Username = username;
        return View();
    }

    // GET /cadastro — só admins (verificado pelo middleware)
    [HttpGet("/cadastro")]
    public async Task<IActionResult> Cadastro()
    {
        try
        {
            var vm = new RegisterViewModel
            {
                Users = await _security.GetAllUsersAsync()
            };
            return View(vm);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao carregar página de cadastro");
            return View(new RegisterViewModel { ErrorMessage = "Erro ao carregar dados." });
        }
    }

    // POST /cadastro — token CSRF validado pelo atributo
    [HttpPost("/cadastro")]
    [ValidateAntiForgeryToken]  // PROTEÇÃO CSRF
    public async Task<IActionResult> Cadastro(RegisterViewModel model)
    {
        try
        {
            // Validação e sanitização de entrada
            if (string.IsNullOrWhiteSpace(model.Username) ||
                string.IsNullOrWhiteSpace(model.Password))
            {
                model.ErrorMessage = "Usuário e senha são obrigatórios.";
                model.Users = await _security.GetAllUsersAsync();
                return View(model);
            }

            // Limita tamanho dos campos
            if (model.Username.Length > 100 || model.Password.Length > 200)
            {
                model.ErrorMessage = "Dados inválidos.";
                model.Users = await _security.GetAllUsersAsync();
                return View(model);
            }

            // Valida papel permitido (whitelist)
            if (model.Role != Roles.Admin && model.Role != Roles.User)
            {
                model.ErrorMessage = "Tipo de usuário inválido.";
                model.Users = await _security.GetAllUsersAsync();
                return View(model);
            }

            // Cria usuário com senha hasheada (Argon2id)
            var created = await _security.CreateUserAsync(
                model.Username.Trim(), model.Password, model.Role);

            if (!created)
            {
                model.ErrorMessage = "Usuário já existe ou erro ao cadastrar.";
                model.Users = await _security.GetAllUsersAsync();
                return View(model);
            }

            _logger.LogInformation("Usuário criado: {User}, role={Role}",
                model.Username, model.Role);

            model.SuccessMessage = $"Usuário '{model.Username}' cadastrado com sucesso!";
            model.Username = string.Empty;
            model.Password = string.Empty;
            model.Users = await _security.GetAllUsersAsync();
            return View(model);
        }
        catch (Exception ex)
        {
            // Trata erro sem expor detalhes
            _logger.LogError(ex, "Erro ao cadastrar usuário");
            model.ErrorMessage = "Ocorreu um erro. Tente novamente.";
            model.Users = await _security.GetAllUsersAsync();
            return View(model);
        }
    }
}
