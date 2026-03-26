using Microsoft.AspNetCore.Mvc;

namespace WebSegura.Controllers;

public class UserController : Controller
{
    // GET /usuarios — só usuários comuns (verificado pelo middleware)
    [HttpGet("/usuarios")]
    public IActionResult Index()
    {
        ViewBag.Username = HttpContext.Session.GetString("Username");
        return View();
    }
}
