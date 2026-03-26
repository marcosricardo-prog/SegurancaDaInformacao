// =============================================================
//  PONTO ÚNICO DE SEGURANÇA — SecurityService.cs
//  Centraliza TODOS os mecanismos de segurança da aplicação:
//    1. Hash de senhas (Argon2id)
//    2. Consultas parametrizadas (prevenção de SQL Injection)
//    3. Proteção CSRF
//    4. Controle de acesso baseado em papéis (RBAC)
//    5. Gerenciamento seguro de sessão
//    6. Tratamento centralizado de erros
// =============================================================

using Isopoh.Cryptography.Argon2;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.Data.Sqlite;
using WebSegura.Models;

namespace WebSegura.Services;

public class SecurityService
{
    private readonly string _connectionString;
    private readonly ILogger<SecurityService> _logger;

    public SecurityService(string connectionString, ILogger<SecurityService> logger)
    {
        _connectionString = connectionString;
        _logger = logger;
    }

    // ─────────────────────────────────────────────────────────
    // 1. HASH DE SENHAS — Argon2id (resistente a brute force)
    // ─────────────────────────────────────────────────────────
    public string HashPassword(string plainPassword)
    {
        // Argon2id: combina resistência a ataques de GPU (Argon2d)
        // e side-channel (Argon2i). Recomendado pelo OWASP.
        return Argon2.Hash(plainPassword);
    }

    public bool VerifyPassword(string plainPassword, string hashedPassword)
    {
        return Argon2.Verify(hashedPassword, plainPassword);
    }

    // ─────────────────────────────────────────────────────────
    // 2. CONSULTAS PARAMETRIZADAS — prevenção de SQL Injection
    //    Nunca concatena strings de usuário em SQL.
    // ─────────────────────────────────────────────────────────
    public async Task<UserModel?> GetUserByUsernameAsync(string username)
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync();

            // Parâmetro @username evita injeção SQL — o valor
            // nunca é interpretado como código SQL pelo banco.
            const string sql = @"
                SELECT Id, Username, PasswordHash, Role
                FROM Users
                WHERE Username = @username";

            using var cmd = new SqliteCommand(sql, connection);
            cmd.Parameters.AddWithValue("@username", username); // parametrizado

            using var reader = await cmd.ExecuteReaderAsync();
            if (!await reader.ReadAsync()) return null;

            return new UserModel
            {
                Id       = reader.GetInt32(0),
                Username = reader.GetString(1),
                PasswordHash = reader.GetString(2),
                Role     = reader.GetString(3)
            };
        }
        catch (Exception ex)
        {
            // Loga erro interno mas NÃO expõe detalhes ao usuário
            _logger.LogError(ex, "Erro interno ao buscar usuário");
            return null;
        }
    }

    public async Task<bool> CreateUserAsync(string username, string plainPassword, string role)
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync();

            // Verifica duplicidade com consulta parametrizada
            const string checkSql = "SELECT COUNT(*) FROM Users WHERE Username = @username";
            using var checkCmd = new SqliteCommand(checkSql, connection);
            checkCmd.Parameters.AddWithValue("@username", username);
            var count = Convert.ToInt32(await checkCmd.ExecuteScalarAsync());
            if (count > 0) return false;

            // Armazena HASH da senha — jamais a senha em texto claro
            var hash = HashPassword(plainPassword);

            // Todos os parâmetros são passados de forma segura
            const string sql = @"
                INSERT INTO Users (Username, PasswordHash, Role)
                VALUES (@username, @hash, @role)";

            using var cmd = new SqliteCommand(sql, connection);
            cmd.Parameters.AddWithValue("@username", username);
            cmd.Parameters.AddWithValue("@hash",     hash);
            cmd.Parameters.AddWithValue("@role",     role);

            await cmd.ExecuteNonQueryAsync();
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro interno ao criar usuário");
            return false;
        }
    }

    public async Task<List<UserModel>> GetAllUsersAsync()
    {
        var users = new List<UserModel>();
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync();
            const string sql = "SELECT Id, Username, Role FROM Users ORDER BY Username";
            using var cmd = new SqliteCommand(sql, connection);
            using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                users.Add(new UserModel
                {
                    Id       = reader.GetInt32(0),
                    Username = reader.GetString(1),
                    Role     = reader.GetString(2)
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro interno ao listar usuários");
        }
        return users;
    }

    // ─────────────────────────────────────────────────────────
    // 3. PROTEÇÃO CSRF — Configurada no Program.cs via
    //    AddAntiforgery() + ValidateAntiForgeryToken.
    //    Aqui ficam helpers de validação customizada.
    // ─────────────────────────────────────────────────────────
    public static void ConfigureAntiforgery(AntiforgeryOptions options)
    {
        // Cookie HttpOnly + Secure: inacessível por JS e só enviado via HTTPS
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite     = SameSiteMode.Strict; // bloqueia envio cross-site
        options.HeaderName = "X-CSRF-TOKEN";
    }

    // ─────────────────────────────────────────────────────────
    // 4. CONTROLE DE ACESSO — verifica papel do usuário.
    //    Usado pelo AccessControlMiddleware antes de cada request.
    // ─────────────────────────────────────────────────────────
    public static bool CanAccess(string? userRole, string path)
    {
        var lowerPath = path.ToLowerInvariant().TrimEnd('/');

        return lowerPath switch
        {
            // Somente administradores autenticados
            "/cadastro" or "/administradores"
                => userRole == Roles.Admin,

            // Somente usuários comuns autenticados
            "/usuarios"
                => userRole == Roles.User,

            // Logout: qualquer usuário autenticado pode encerrar sessão
            "/logout"
                => !string.IsNullOrEmpty(userRole),

            // Login é público
            "/login" or "/"
                => true,

            // Nega por padrão (deny-by-default)
            _ => false
        };
    }

    // ─────────────────────────────────────────────────────────
    // 5. GERENCIAMENTO DE SESSÃO — parâmetros seguros.
    //    Configuração aplicada no Program.cs.
    // ─────────────────────────────────────────────────────────
    public static void ConfigureSession(SessionOptions options)
    {
        // Expira por inatividade — reduz janela de ataque
        options.IdleTimeout     = TimeSpan.FromMinutes(15);
        options.Cookie.HttpOnly = true;   // inacessível via JavaScript
        options.Cookie.IsEssential = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // só HTTPS
        options.Cookie.SameSite     = SameSiteMode.Strict;
    }

    // ─────────────────────────────────────────────────────────
    // 6. INICIALIZAÇÃO DO BANCO — cria schema e admin padrão
    // ─────────────────────────────────────────────────────────
    public async Task InitializeDatabaseAsync()
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync();

            const string createTable = @"
                CREATE TABLE IF NOT EXISTS Users (
                    Id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    Username     TEXT    NOT NULL UNIQUE,
                    PasswordHash TEXT    NOT NULL,
                    Role         TEXT    NOT NULL CHECK(Role IN ('admin','user')),
                    CreatedAt    TEXT    NOT NULL DEFAULT (datetime('now'))
                );";

            using var cmd = new SqliteCommand(createTable, connection);
            await cmd.ExecuteNonQueryAsync();

            // Cria admin padrão se não existir
            const string checkAdmin = "SELECT COUNT(*) FROM Users WHERE Username = 'admin'";
            using var checkCmd = new SqliteCommand(checkAdmin, connection);
            var count = Convert.ToInt32(await checkCmd.ExecuteScalarAsync());

            if (count == 0)
            {
                var hash = HashPassword("Admin@123");
                const string insertAdmin = @"
                    INSERT INTO Users (Username, PasswordHash, Role)
                    VALUES ('admin', @hash, 'admin')";
                using var insertCmd = new SqliteCommand(insertAdmin, connection);
                insertCmd.Parameters.AddWithValue("@hash", hash);
                await insertCmd.ExecuteNonQueryAsync();
                _logger.LogInformation("Usuário admin padrão criado.");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao inicializar banco de dados");
            throw;
        }
    }
}

// Constantes de papéis — evita strings mágicas
public static class Roles
{
    public const string Admin = "admin";
    public const string User  = "user";
}
