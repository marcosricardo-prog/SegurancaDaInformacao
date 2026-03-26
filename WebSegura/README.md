# WebSegura — Aplicação Web Segura (ASP.NET Core 8 + C#)

## Pré-requisitos
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8) instalado

---

## Como executar

```bash
# 1. Restaurar pacotes
cd WebSegura
dotnet restore

# 2. Executar (gera certificado HTTPS automático)
dotnet run

# 3. Acesse no navegador:
# https://localhost:7001/login
```

Na primeira execução, o banco SQLite é criado automaticamente com um usuário admin padrão:
- **Usuário:** `admin`
- **Senha:** `Admin@123`

---

## Estrutura do projeto

```
WebSegura/
├── Program.cs                          ← Configuração central de segurança
├── Services/
│   └── SecurityService.cs              ← PONTO ÚNICO de segurança
├── Middleware/
│   └── AccessControlMiddleware.cs      ← RBAC em todos os requests
├── Controllers/
│   ├── AccountController.cs            ← Login / Logout
│   ├── AdminController.cs              ← /administradores e /cadastro
│   └── UserController.cs              ← /usuarios
├── Models/
│   └── UserModel.cs
├── Views/
│   ├── Account/Login.cshtml
│   ├── Admin/Index.cshtml              ← /administradores
│   ├── Admin/Cadastro.cshtml           ← /cadastro
│   └── User/Index.cshtml              ← /usuarios
└── wwwroot/css/site.css
```

---

## Mecanismos de segurança implementados

### 1. Ponto único de segurança (`SecurityService.cs`)
Toda a lógica de segurança está centralizada em `Services/SecurityService.cs`:
- Hash de senhas (Argon2id)
- Consultas parametrizadas
- Configuração de CSRF
- Lógica de controle de acesso
- Configuração de sessão

### 2. Prevenção de SQL Injection
Todas as queries usam parâmetros (`@username`, `@hash`, `@role`).
**Jamais concatena strings de usuário em SQL.**

```csharp
cmd.Parameters.AddWithValue("@username", username); // parametrizado
```

### 3. Proteção CSRF
- `AddAntiforgery()` no `Program.cs` com cookie `SameSite=Strict`, `HttpOnly`, `Secure`
- Todos os formulários POST usam `@Html.AntiForgeryToken()`
- Todos os controllers POST têm `[ValidateAntiForgeryToken]`

### 4. Controle de Acesso (RBAC)
- `AccessControlMiddleware` intercepta **todos** os requests
- Lógica `deny-by-default`: qualquer rota não explicitamente permitida é bloqueada
- Administradores → `/administradores`, `/cadastro`
- Usuários comuns → `/usuarios`

### 5. Segurança de Sessão
- `Session.Clear()` + regeneração de contexto após login (previne Session Fixation)
- Timeout de inatividade: **15 minutos**
- Cookie: `HttpOnly`, `Secure`, `SameSite=Strict`

### 6. Hash de senhas — Argon2id
- Biblioteca: `Isopoh.Cryptography.Argon2`
- Algoritmo recomendado pelo OWASP (vencedor do PHC — Password Hashing Competition)
- Hashes armazenados no banco; jamais senhas em texto claro

### 7. Tratamento de erros
- Todos os controllers usam `try/catch`
- Erros internos são logados mas **não exibidos ao usuário**
- Mensagens genéricas: "Ocorreu um erro. Tente novamente."
- Em produção: `UseExceptionHandler("/erro")` suprime stack traces

---

## Script SQL (gerado automaticamente pelo código, mas equivalente)

```sql
CREATE TABLE IF NOT EXISTS Users (
    Id           INTEGER PRIMARY KEY AUTOINCREMENT,
    Username     TEXT    NOT NULL UNIQUE,
    PasswordHash TEXT    NOT NULL,
    Role         TEXT    NOT NULL CHECK(Role IN ('admin','user')),
    CreatedAt    TEXT    NOT NULL DEFAULT (datetime('now'))
);
```

---

## Regras de acesso

| Página            | Não autenticado | Admin | Usuário comum |
|-------------------|:--------------:|:-----:|:-------------:|
| `/login`          | ✅ | ✅ | ✅ |
| `/administradores`| ❌ | ✅ | ❌ |
| `/cadastro`       | ❌ | ✅ | ❌ |
| `/usuarios`       | ❌ | ❌ | ✅ |

---

IFSP - Campus Capivari
>Aplicação criada para Atividade Modulo 3

>PROJETO DE SEGURANÇA DA INFORMAÇÃO 

>Marcos Ricardo de Souza - CV3101584

>Prof. Rafael Fernando Diorio 

