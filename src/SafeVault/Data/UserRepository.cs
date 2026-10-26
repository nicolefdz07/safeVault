using Microsoft.Data.Sqlite;

namespace SafeVault.Data;

/// <summary>
/// All database access goes through parameterized queries. User input is NEVER
/// concatenated into SQL text, which prevents SQL injection.
/// </summary>
public class UserRepository
{
    private const string Columns = "UserID, Username, Email, PasswordHash, Role";
    private readonly string _connectionString;

    public UserRepository(string connectionString) => _connectionString = connectionString;

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        return connection;
    }

    public void Initialize()
    {
        using var connection = Open();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = @"CREATE TABLE IF NOT EXISTS Users (
            UserID       INTEGER PRIMARY KEY AUTOINCREMENT,
            Username     TEXT NOT NULL UNIQUE COLLATE NOCASE,
            Email        TEXT NOT NULL,
            PasswordHash TEXT NOT NULL,
            Role         TEXT NOT NULL CHECK (Role IN ('user','admin')))";
        cmd.ExecuteNonQuery();
    }

    /// <returns>false if the username already exists.</returns>
    public bool Create(User user)
    {
        try
        {
            using var connection = Open();
            using var cmd = connection.CreateCommand();
            cmd.CommandText =
                "INSERT INTO Users (Username, Email, PasswordHash, Role) VALUES (@username, @email, @hash, @role)";
            cmd.Parameters.AddWithValue("@username", user.Username);
            cmd.Parameters.AddWithValue("@email", user.Email);
            cmd.Parameters.AddWithValue("@hash", user.PasswordHash);
            cmd.Parameters.AddWithValue("@role", user.Role);
            cmd.ExecuteNonQuery();
            return true;
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19) // SQLITE_CONSTRAINT
        {
            return false;
        }
    }

    public User? FindByUsername(string username)
    {
        using var connection = Open();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = $"SELECT {Columns} FROM Users WHERE Username = @username LIMIT 1";
        cmd.Parameters.AddWithValue("@username", username);
        using var reader = cmd.ExecuteReader();
        return reader.Read() ? Map(reader) : null;
    }

    /// <summary>Prefix search. LIKE wildcards in the input are escaped so they are treated literally.</summary>
    public IReadOnlyList<User> SearchByUsernamePrefix(string prefix)
    {
        var escaped = prefix.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");
        using var connection = Open();
        using var cmd = connection.CreateCommand();
        cmd.CommandText =
            $"SELECT {Columns} FROM Users WHERE Username LIKE @pattern ESCAPE '\\' ORDER BY Username LIMIT 50";
        cmd.Parameters.AddWithValue("@pattern", escaped + "%");
        return ReadAll(cmd);
    }

    public IReadOnlyList<User> GetAll()
    {
        using var connection = Open();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = $"SELECT {Columns} FROM Users ORDER BY Username LIMIT 500";
        return ReadAll(cmd);
    }

    private static List<User> ReadAll(SqliteCommand cmd)
    {
        var users = new List<User>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read()) users.Add(Map(reader));
        return users;
    }

    private static User Map(SqliteDataReader r) =>
        new(r.GetInt64(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetString(4));
}
