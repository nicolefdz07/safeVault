using Microsoft.Data.Sqlite;
using SafeVault.Data;

namespace SafeVault.Tests;

[TestFixture]
public class TestSqlInjection
{
    private string _dbPath = "";
    private UserRepository _repo = null!;

    [SetUp]
    public void SetUp()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"safevault-sqli-{Guid.NewGuid():N}.db");
        _repo = new UserRepository($"Data Source={_dbPath}");
        _repo.Initialize();
        _repo.Create(new User(0, "alice", "alice@example.com", "hash-a", Roles.User));
        _repo.Create(new User(0, "bob", "bob@example.com", "hash-b", Roles.User));
    }

    [TearDown]
    public void TearDown()
    {
        SqliteConnection.ClearAllPools();
        if (File.Exists(_dbPath)) File.Delete(_dbPath);
    }

    [TestCase("' OR '1'='1")]
    [TestCase("alice' --")]
    [TestCase("alice'; DROP TABLE Users; --")]
    [TestCase("' UNION SELECT UserID, Username, Email, PasswordHash, Role FROM Users --")]
    public void FindByUsername_InjectionPayload_ReturnsNothing(string payload) =>
        Assert.That(_repo.FindByUsername(payload), Is.Null);

    [Test]
    public void DropTablePayload_DoesNotDestroyData()
    {
        _repo.FindByUsername("'; DROP TABLE Users; --");
        Assert.That(_repo.FindByUsername("alice"), Is.Not.Null);
        Assert.That(_repo.GetAll(), Has.Count.EqualTo(2));
    }

    [Test]
    public void Create_StoresInjectionStringAsPlainData_AndDoesNotExecuteIt()
    {
        const string payload = "x'); DROP TABLE Users; --";
        _repo.Create(new User(0, payload, "evil@example.com", "hash", Roles.User));
        Assert.That(_repo.GetAll(), Has.Count.EqualTo(3));
        Assert.That(_repo.FindByUsername(payload)?.Username, Is.EqualTo(payload));
    }

    [Test]
    public void Search_LikeWildcards_AreTreatedLiterally()
    {
        Assert.That(_repo.SearchByUsernamePrefix("%"), Is.Empty);
        Assert.That(_repo.SearchByUsernamePrefix("_"), Is.Empty);
        Assert.That(_repo.SearchByUsernamePrefix("al").Select(u => u.Username), Is.EqualTo(new[] { "alice" }));
    }

    [Test]
    public void DuplicateUsername_IsRejected_CaseInsensitively() =>
        Assert.That(_repo.Create(new User(0, "ALICE", "x@example.com", "h", Roles.User)), Is.False);
}
