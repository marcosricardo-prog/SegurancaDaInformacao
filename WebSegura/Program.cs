// =============================================================
//  Program.cs — Configuração principal da aplicação
//  Todos os mecanismos de segurança são registrados aqui,
//  utilizando o SecurityService como ponto único.
// =============================================================

using WebSegura.Middleware;
using WebSegura.Services;

var builder = WebApplication.CreateBuilder(args);

// ── String de conexão SQLite ─────────────────────────────────
var dbPath = Path.Combine(AppContext.BaseDirectory, "websegura.db");
var connectionString = $"Data Source={dbPath}";

// ── Logging ──────────────────────────────────────────────────
builder.Logging.ClearProviders();
builder.Logging.AddConsole();

// ── MVC ──────────────────────────────────────────────────────
builder.Services.AddControllersWithViews();

// ── Serviço de segurança (ponto único) ───────────────────────
builder.Services.AddSingleton<SecurityService>(sp =>
    new SecurityService(connectionString,
        sp.GetRequiredService<ILogger<SecurityService>>()));

// ── PROTEÇÃO CSRF ─────────────────────────────────────────────
// Configura tokens antifalsificação via SecurityService
builder.Services.AddAntiforgery(SecurityService.ConfigureAntiforgery);

// ── SESSÃO SEGURA ─────────────────────────────────────────────
// Usa parâmetros definidos no SecurityService:
// idle timeout 15min, HttpOnly, Secure, SameSite=Strict
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(SecurityService.ConfigureSession);

// ── HTTPS ─────────────────────────────────────────────────────
builder.Services.AddHttpsRedirection(options =>
{
    options.RedirectStatusCode = StatusCodes.Status301MovedPermanently;
    options.HttpsPort = 7001;
});

// ── HSTS (HTTP Strict Transport Security) ─────────────────────
builder.Services.AddHsts(options =>
{
    options.Preload           = true;
    options.IncludeSubDomains = true;
    options.MaxAge            = TimeSpan.FromDays(365);
});

var app = builder.Build();

// ── Pipeline de segurança ────────────────────────────────────

if (!app.Environment.IsDevelopment())
{
    // Handler global de erros — não expõe stack trace ao usuário
    app.UseExceptionHandler("/erro");
    app.UseHsts();
}
else
{
    // Em dev, mostra página de exceção para facilitar debug
    app.UseDeveloperExceptionPage();
}

// Força HTTPS
app.UseHttpsRedirection();

// Arquivos estáticos
app.UseStaticFiles();

// Sessão (antes do middleware de controle de acesso)
app.UseSession();

// ── CONTROLE DE ACESSO (RBAC) — middleware customizado ───────
// Intercepta todos os requests e aplica deny-by-default
app.UseMiddleware<AccessControlMiddleware>();

app.UseRouting();
app.MapControllers();

// Redireciona raiz para /login
app.MapGet("/", () => Results.Redirect("/login"));

// Página genérica de erro (não exibe detalhes técnicos)
app.MapGet("/erro", async ctx =>
{
    ctx.Response.StatusCode = 500;
    await ctx.Response.WriteAsync(
        "Ocorreu um erro interno. Por favor, tente novamente mais tarde.");
});

// ── Inicializa banco de dados ─────────────────────────────────
var security = app.Services.GetRequiredService<SecurityService>();
await security.InitializeDatabaseAsync();

app.Run();
