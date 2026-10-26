using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace SafeVault.Tests;

[TestFixture]
public class TestAuthorization
{
    private SafeVaultFactory _factory = null!;
    private HttpClient _client = null!;
    private const string GoodPassword = "Str0ngPassw0rd";

    [OneTimeSetUp]
    public void OneTimeSetUp()
    {
        _factory = new SafeVaultFactory();
        _client = _factory.CreateClient();
    }

    [OneTimeTearDown]
    public void OneTimeTearDown()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    private Task<HttpResponseMessage> Register(string user, string email, string password) =>
        _client.PostAsJsonAsync("/api/auth/register", new { username = user, email, password });

    private async Task<string> LoginToken(string user, string password)
    {
        var res = await _client.PostAsJsonAsync("/api/auth/login", new { username = user, password });
        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        return json.GetProperty("token").GetString()!;
    }

    private Task<HttpResponseMessage> Get(string url, string? token = null)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, url);
        if (token != null) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return _client.SendAsync(req);
    }

    // ---------- registration / login ----------

    [Test]
    public async Task Register_ValidUser_Returns201()
    {
        var res = await Register("reg_ok", "reg_ok@example.com", GoodPassword);
        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.Created));
    }

    [Test]
    public async Task Register_Duplicate_Returns409()
    {
        await Register("dup_user", "dup@example.com", GoodPassword);
        var res = await Register("dup_user", "dup@example.com", GoodPassword);
        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.Conflict));
    }

    [TestCase("<script>alert(1)</script>")]
    [TestCase("' OR '1'='1")]
    [TestCase("x'; DROP TABLE Users; --")]
    public async Task Register_MaliciousUsername_Returns400(string payload)
    {
        var res = await Register(payload, "evil@example.com", GoodPassword);
        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task Register_WeakPassword_Returns400()
    {
        var res = await Register("weak_pw", "weak@example.com", "password");
        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task Register_CannotChooseAdminRole()
    {
        // Extra "role" field must be ignored: self-registered users are always plain users.
        var res = await _client.PostAsJsonAsync("/api/auth/register",
            new { username = "sneaky", email = "s@example.com", password = GoodPassword, role = "admin" });
        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.Created));
        var token = await LoginToken("sneaky", GoodPassword);
        Assert.That((await Get("/api/admin/users", token)).StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }

    [Test]
    public async Task Login_WrongPassword_And_UnknownUser_ReturnSameGenericError()
    {
        await Register("login_user", "l@example.com", GoodPassword);
        var wrong = await _client.PostAsJsonAsync("/api/auth/login", new { username = "login_user", password = "WrongPassw0rd!" });
        var unknown = await _client.PostAsJsonAsync("/api/auth/login", new { username = "no_such_user", password = "WrongPassw0rd!" });
        Assert.That(wrong.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That(unknown.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That(await wrong.Content.ReadAsStringAsync(), Is.EqualTo(await unknown.Content.ReadAsStringAsync()));
    }

    [Test]
    public async Task Login_SqlInjectionPayload_Returns401()
    {
        var res = await _client.PostAsJsonAsync("/api/auth/login", new { username = "' OR '1'='1' --", password = "x" });
        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    // ---------- RBAC ----------

    [Test]
    public async Task Vault_WithoutToken_Returns401() =>
        Assert.That((await Get("/api/vault/me")).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));

    [Test]
    public async Task Vault_WithGarbageToken_Returns401() =>
        Assert.That((await Get("/api/vault/me", "not.a.jwt")).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));

    [Test]
    public async Task Vault_AsUser_Returns200_WithOwnIdentity()
    {
        await Register("vault_user", "v@example.com", GoodPassword);
        var token = await LoginToken("vault_user", GoodPassword);
        var res = await Get("/api/vault/me", token);
        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        Assert.That(json.GetProperty("username").GetString(), Is.EqualTo("vault_user"));
        Assert.That(json.GetProperty("role").GetString(), Is.EqualTo("user"));
    }

    [Test]
    public async Task Admin_AsNormalUser_Returns403()
    {
        await Register("plain_user", "p@example.com", GoodPassword);
        var token = await LoginToken("plain_user", GoodPassword);
        Assert.That((await Get("/api/admin/users", token)).StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }

    [Test]
    public async Task Admin_WithoutToken_Returns401() =>
        Assert.That((await Get("/api/admin/users")).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));

    [Test]
    public async Task Admin_AsAdmin_Returns200_AndNeverLeaksPasswordHashes()
    {
        var token = await LoginToken("admin", SafeVaultFactory.AdminPassword);
        var res = await Get("/api/admin/users", token);
        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var body = await res.Content.ReadAsStringAsync();
        Assert.That(body, Does.Contain("admin"));
        Assert.That(body.ToLowerInvariant(), Does.Not.Contain("passwordhash"));
        Assert.That(body, Does.Not.Contain("$2"));
    }

    [Test]
    public async Task AdminSearch_RejectsInjectionPayload_AndAcceptsPrefix()
    {
        var token = await LoginToken("admin", SafeVaultFactory.AdminPassword);
        Assert.That((await Get("/api/admin/users/search?q=" + Uri.EscapeDataString("' OR 1=1 --"), token)).StatusCode,
            Is.EqualTo(HttpStatusCode.BadRequest));
        Assert.That((await Get("/api/admin/users/search?q=adm", token)).StatusCode,
            Is.EqualTo(HttpStatusCode.OK));
    }

    // ---------- security headers ----------

    [Test]
    public async Task Responses_IncludeSecurityHeaders()
    {
        var res = await Get("/api/vault/me");
        Assert.That(res.Headers.Contains("Content-Security-Policy"), Is.True);
        Assert.That(res.Headers.Contains("X-Content-Type-Options"), Is.True);
        Assert.That(res.Headers.Contains("X-Frame-Options"), Is.True);
    }
}
