using WebSegura.Services;

namespace WebSegura.Models;

public class UserModel
{
    public int    Id           { get; set; }
    public string Username     { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string Role         { get; set; } = string.Empty;
}

public class LoginViewModel
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string? ErrorMessage { get; set; }
}

public class RegisterViewModel
{
    public string Username     { get; set; } = string.Empty;
    public string Password     { get; set; } = string.Empty;
    public string Role         { get; set; } = Roles.User;
    public string? ErrorMessage  { get; set; }
    public string? SuccessMessage { get; set; }
    public List<UserModel> Users { get; set; } = new();
}
