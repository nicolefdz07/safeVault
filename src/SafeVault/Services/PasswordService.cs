using BCrypt.Net;

namespace SafeVault.Services;

public static class PasswordService
{
    private const int WorkFactor = 12;

    // Verified when the user does not exist so response time doesn't reveal valid usernames.
    private static readonly string DummyHash = Hash("dummy-password-for-timing-1A");

    public static string Hash(string password) => BCrypt.Net.BCrypt.HashPassword(password, WorkFactor);

    public static bool Verify(string password, string? hash)
    {
        try { return BCrypt.Net.BCrypt.Verify(password, hash ?? DummyHash) && hash is not null; }
        catch (SaltParseException) { return false; }
    }
}
