using SafeVault.Services;

namespace SafeVault.Tests;

[TestFixture]
public class TestXss
{
    [Test]
    public void ScriptTag_IsHtmlEncoded()
    {
        var result = InputValidator.SanitizeForHtml("<script>alert('XSS')</script>");
        Assert.That(result, Does.Not.Contain("<script>"));
        Assert.That(result, Does.Contain("&lt;script&gt;"));
    }

    [TestCase("<img src=x onerror=alert(1)>")]
    [TestCase("\"><svg/onload=alert(1)>")]
    [TestCase("<a href=\"javascript:alert(1)\">x</a>")]
    public void Payloads_NeverKeepRawAngleBracketsOrQuotes(string payload)
    {
        var result = InputValidator.SanitizeForHtml(payload);
        Assert.That(result, Does.Not.Contain("<"));
        Assert.That(result, Does.Not.Contain(">"));
        Assert.That(result, Does.Not.Contain("\""));
    }

    [Test]
    public void NullInput_ReturnsEmptyString() =>
        Assert.That(InputValidator.SanitizeForHtml(null), Is.EqualTo(string.Empty));

    [Test]
    public void SafeText_IsUnchanged() =>
        Assert.That(InputValidator.SanitizeForHtml("alice_01"), Is.EqualTo("alice_01"));
}
