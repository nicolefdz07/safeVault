using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Services;

namespace SafeVault.Controllers;

/// <summary>Any authenticated user (role user or admin).</summary>
[ApiController]
[Route("api/vault")]
[Authorize]
public class VaultController : ControllerBase
{
    [HttpGet("me")]
    public IActionResult Me() => Ok(new
    {
        username = User.Identity?.Name,
        role = User.FindFirst("role")?.Value
    });

    /// <summary>HTML page that echoes user data; every value is HTML-encoded to prevent XSS.</summary>
    [HttpGet("profile")]
    public ContentResult Profile()
    {
        var name = InputValidator.SanitizeForHtml(User.Identity?.Name);
        var role = InputValidator.SanitizeForHtml(User.FindFirst("role")?.Value);
        return Content(
            $"<!doctype html><html><body><h1>Welcome, {name}</h1><p>Role: {role}</p></body></html>",
            "text/html");
    }
}
