using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;

namespace SafeVault.Tests;

/// <summary>
/// Boots the real app against a throw-away SQLite file. Configuration is passed through
/// environment variables because Program.cs reads it while the host is being built.
/// </summary>
public class SafeVaultFactory : WebApplicationFactory<Program>
{
    public const string AdminPassword = "Adm1n-Test-Passw0rd!";
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"safevault-it-{Guid.NewGuid():N}.db");

    public SafeVaultFactory()
    {
        Environment.SetEnvironmentVariable("ConnectionStrings__Default", $"Data Source={_dbPath}");
        Environment.SetEnvironmentVariable("Seed__AdminPassword", AdminPassword);
        Environment.SetEnvironmentVariable("RateLimit__AuthPerMinute", "1000"); // tests share one client IP
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        Environment.SetEnvironmentVariable("ConnectionStrings__Default", null);
        Environment.SetEnvironmentVariable("Seed__AdminPassword", null);
        Environment.SetEnvironmentVariable("RateLimit__AuthPerMinute", null);
        try { SqliteConnection.ClearAllPools(); File.Delete(_dbPath); } catch { /* best effort */ }
    }
}
