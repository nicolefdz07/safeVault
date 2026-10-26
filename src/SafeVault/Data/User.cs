namespace SafeVault.Data;

public static class Roles
{
    public const string User = "user";
    public const string Admin = "admin";
}

public record User(long Id, string Username, string Email, string PasswordHash, string Role);
