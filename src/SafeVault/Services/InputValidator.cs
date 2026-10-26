using System.Net;
using System.Text.RegularExpressions;

namespace SafeVault.Services;

/// <summary>
/// Allow-list validation (reject anything not explicitly permitted) plus HTML encoding for output.
/// Note: patterns end with \z (not $) because $ also matches before a trailing newline.
/// </summary>
public static class InputValidator
{
    private static readonly TimeSpan Timeout = TimeSpan.FromMilliseconds(100);

    private static readonly Regex UsernameRegex =
        new(@"^[A-Za-z0-9_.\-]{3,32}\z", RegexOptions.Compiled, Timeout);

    private static readonly Regex SearchRegex =
        new(@"^[A-Za-z0-9_.\-]{1,32}\z", RegexOptions.Compiled, Timeout);

    private static readonly Regex EmailRegex =
        new(@"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\z", RegexOptions.Compiled, Timeout);

    public static bool IsValidUsername(string? value) =>
        !string.IsNullOrEmpty(value) && UsernameRegex.IsMatch(value);

    public static bool IsValidSearchTerm(string? value) =>
        !string.IsNullOrEmpty(value) && SearchRegex.IsMatch(value);

    public static bool IsValidEmail(string? value) =>
        !string.IsNullOrEmpty(value) && value.Length <= 254 && !value.Contains("..") && EmailRegex.IsMatch(value);

    public static bool IsValidPassword(string? value) =>
        value is { Length: >= 10 and <= 128 }
        && value.Any(char.IsUpper) && value.Any(char.IsLower) && value.Any(char.IsDigit);

    /// <summary>Encode untrusted text before putting it in an HTML page (prevents XSS).</summary>
    public static string SanitizeForHtml(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);
}
