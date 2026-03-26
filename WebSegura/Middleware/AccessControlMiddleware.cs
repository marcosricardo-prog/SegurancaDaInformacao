// =============================================================
//  AccessControlMiddleware.cs
//  Intercepta TODOS os requests e aplica controle de acesso
//  baseado em papéis (RBAC) antes de qualquer controller.
//  Implementa "deny-by-default" — qualquer rota não listada
//  no SecurityService.CanAccess() é bloqueada.
// =============================================================

using WebSegura.Services;

namespace WebSegura.Middleware;

public class AccessControlMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<AccessControlMiddleware> _logger;

    public AccessControlMiddleware(RequestDelegate next, ILogger<AccessControlMiddleware> logger)
    {
        _next  = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            var path     = context.Request.Path.Value ?? "/";
            var userRole = context.Session.GetString("UserRole");

            // Permite arquivos estáticos sem verificação
            if (path.StartsWith("/css") || path.StartsWith("/js") ||
                path.StartsWith("/lib") || path.StartsWith("/favicon"))
            {
                await _next(context);
                return;
            }

            // Verifica acesso usando a lógica centralizada no SecurityService
            if (!SecurityService.CanAccess(userRole, path))
            {
                _logger.LogWarning(
                    "Acesso negado: path={Path}, role={Role}, IP={IP}",
                    path, userRole ?? "anônimo",
                    context.Connection.RemoteIpAddress);

                // Usuário não autenticado → redireciona para login
                if (string.IsNullOrEmpty(userRole))
                {
                    context.Response.Redirect("/login?denied=1");
                    return;
                }

                // Usuário autenticado sem permissão → 403
                context.Response.StatusCode = 403;
                context.Response.ContentType = "text/plain; charset=utf-8";
                await context.Response.WriteAsync(
                    "Acesso negado. Você não tem permissão para acessar esta página.",
                    System.Text.Encoding.UTF8);
                return;
            }

            await _next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro no middleware de controle de acesso");
            // Não expõe detalhes do erro — mensagem genérica
            context.Response.StatusCode = 500;
            context.Response.ContentType = "text/plain; charset=utf-8";
            await context.Response.WriteAsync("Ocorreu um erro interno. Tente novamente.", System.Text.Encoding.UTF8);
        }
    }
}
