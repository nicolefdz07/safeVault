using SafeVault.Services;

namespace SafeVault.Tests;

[TestFixture]
public class TestInputValidation
{
    [TestCase("alice")]
    [TestCase("bob_smith-01")]
    [TestCase("a.b.c")]
    public void Username_Valid_IsAccepted(string value) =>
        Assert.That(InputValidator.IsValidUsername(value), Is.True);

    [TestCase("")]
    [TestCase("ab")]
    [TestCase("has space")]
    [TestCase("alice\n")] // trailing newline must not slip past the regex
    [TestCase("this_username_is_definitely_longer_than_32_chars")]
    public void Username_Invalid_IsRejected(string value) =>
        Assert.That(InputValidator.IsValidUsername(value), Is.False);

    [Test]
    public void Username_Null_IsRejected() => Assert.That(InputValidator.IsValidUsername(null), Is.False);

    [TestCase("user@example.com")]
    [TestCase("first.last+tag@sub.example.org")]
    public void Email_Valid_IsAccepted(string value) =>
        Assert.That(InputValidator.IsValidEmail(value), Is.True);

    [TestCase("not-an-email")]
    [TestCase("a@b")]
    [TestCase("a..b@example.com")]
    [TestCase("user@example.com<script>")]
    [TestCase("user@example.com\n")]
    public void Email_Invalid_IsRejected(string value) =>
        Assert.That(InputValidator.IsValidEmail(value), Is.False);

    [TestCase("Str0ngPassw0rd")]
    [TestCase("Another-Good-1-Pass")]
    public void Password_Strong_IsAccepted(string value) =>
        Assert.That(InputValidator.IsValidPassword(value), Is.True);

    [TestCase("short1A")]
    [TestCase("alllowercase123")]
    [TestCase("ALLUPPERCASE123")]
    [TestCase("NoDigitsHereAtAll")]
    public void Password_Weak_IsRejected(string value) =>
        Assert.That(InputValidator.IsValidPassword(value), Is.False);

    [TestCase("' OR '1'='1")]
    [TestCase("admin'--")]
    [TestCase("'; DROP TABLE Users; --")]
    [TestCase("<script>alert('XSS')</script>")]
    [TestCase("\"><svg/onload=alert(1)>")]
    public void MaliciousPayloads_AreRejectedAsUsernames(string payload) =>
        Assert.That(InputValidator.IsValidUsername(payload), Is.False);

    [TestCase("%")]
    [TestCase("a' OR 1=1 --")]
    [TestCase("<b>")]
    public void SearchTerm_WithSpecialCharacters_IsRejected(string value) =>
        Assert.That(InputValidator.IsValidSearchTerm(value), Is.False);
}
